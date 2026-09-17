using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.Linq;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    // OCSP revocation checking routed THROUGH Tor (never direct).
    //
    // Why this exists: the upstream-TLS validation in the inspection path
    // uses X509RevocationMode.NoCheck because a framework-driven OCSP/CRL
    // fetch would go out DIRECT and leak the destination outside Tor. That
    // left revocation unchecked (chain + expiry + hostname only). This class
    // closes the gap without the leak: it builds the OCSP request itself,
    // POSTs it to the responder over a fresh Tor circuit (SOCKS domain mode,
    // so the responder hostname itself is resolved at the exit, never
    // locally), and parses the response locally.
    //
    // Semantics are browser-style soft-fail, documented honestly:
    // - GOOD (or no OCSP URL, or responder unreachable/broken) => NOT
    //   revoked (false). Connectivity through Tor is preserved.
    // - REVOKED with a signature that verifies against the issuer (or a
    //   properly delegated responder) => revoked (true). The caller fails
    //   the tunnel CLOSED on true.
    // - REVOKED with an unverifiable signature => treated as unknown (false:
    //   anyone on-path can forge bytes, so an unverified "revoked" proves
    //   nothing; blocking on it would hand every exit a kill-switch).
    //
    // Results are cached per (issuer, serial): GOOD until nextUpdate (clamped
    // 5min..24h), REVOKED for 24h, lookup failures for 5min. Never throws
    // except OperationCanceledException (cancellation flows to the caller).
    public static class MitmOcsp
    {
        public enum CertStatus { Good, Revoked, Unknown }

        public sealed record OcspSingleResult(
            CertStatus Status,
            byte[]? TbsResponseData,
            byte[]? Signature,
            string? SignatureOid,
            List<byte[]> ResponderCerts,
            DateTimeOffset? NextUpdate);

        const string OidSha1 = "1.3.14.3.2.26";
        const string OidOcspBasicResponse = "1.3.6.1.5.5.7.48.1.1";
        const string OidAia = "1.3.6.1.5.5.7.1.1";
        const string OidOcspMethod = "1.3.6.1.5.5.7.48.1";
        const string OidOcspSigningEku = "1.3.6.1.5.5.7.3.9";
        // DER encoding of the OCSPSigning EKU OID, for a byte search inside
        // a responder cert's EKU extension.
        static readonly byte[] OcspSigningEkuDer = { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

        static readonly ConcurrentDictionary<string, (bool revoked, DateTimeOffset expires)> _cache = new();
        static readonly TimeSpan NegCacheTtl = TimeSpan.FromMinutes(5);
        static readonly TimeSpan MaxGoodTtl = TimeSpan.FromHours(24);
        static readonly TimeSpan RevokedTtl = TimeSpan.FromHours(24);
        static readonly TimeSpan FetchTimeout = TimeSpan.FromSeconds(12);
        const int MaxHttpBody = 64 * 1024;
        // Unbounded growth on long runs (distinct issuer+serial per origin):
        // cap + opportunistic expired-entry sweep on insert.
        const int MaxCacheEntries = 2000;

        static void CacheSet(string key, (bool revoked, DateTimeOffset expires) value)
        {
            try
            {
                _cache[key] = value;
                if (_cache.Count > MaxCacheEntries)
                {
                    var now = DateTimeOffset.UtcNow;
                    foreach (var kv in _cache)
                    {
                        if (kv.Value.expires <= now) _cache.TryRemove(kv.Key, out _);
                        if (_cache.Count <= MaxCacheEntries) break;
                    }
                    // Still over cap (all fresh): evict arbitrary oldest batch.
                    if (_cache.Count > MaxCacheEntries)
                    {
                        var over = _cache.Count - MaxCacheEntries;
                        foreach (var kv in _cache)
                        {
                            if (over-- <= 0) break;
                            _cache.TryRemove(kv.Key, out _);
                        }
                    }
                }
            }
            catch { try { _cache[key] = value; } catch { } }
        }

        public static int CacheCount => _cache.Count;
        public static void ClearCache() => _cache.Clear();

        // ---- entry point ----

        public static async Task<bool> IsRevokedByTorAsync(
            X509Certificate2 leaf,
            X509Certificate2? issuer,
            Func<string, int, CancellationToken, Task<TcpClient?>> dialTor,
            CancellationToken ct)
        {
            try
            {
                if (leaf == null || issuer == null || dialTor == null) return false;
                var serial = LeafSerial(leaf);
                var nameDer = IssuerNameDer(leaf);
                var keyHash = Sha1(IssuerKeyBytes(issuer));
                var nameHash = Sha1(nameDer);
                var key = CacheKey(keyHash, serial);

                if (_cache.TryGetValue(key, out var hit))
                {
                    if (hit.expires > DateTimeOffset.UtcNow) return hit.revoked;
                    _cache.TryRemove(key, out _);
                }

                var urls = GetOcspUrls(leaf);
                if (urls.Count == 0) return false;

                byte[] req;
                try { req = BuildRequest(nameHash, keyHash, serial); }
                catch { return false; }

                foreach (var url in urls.Take(3))
                {
                    ct.ThrowIfCancellationRequested();
                    byte[]? resp = null;
                    try { resp = await FetchOcspAsync(url, req, dialTor, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch { continue; }
                    if (resp == null || resp.Length == 0) continue;
                    OcspSingleResult? found;
                    try { found = FindSingleResponse(resp, nameHash, keyHash, serial); }
                    catch { continue; }
                    if (found == null) continue;
                    if (found.Status == CertStatus.Good)
                    {
                        var ttl = ClampTtl(found.NextUpdate);
                        CacheSet(key, (false, DateTimeOffset.UtcNow + ttl));
                        return false;
                    }
                    if (found.Status == CertStatus.Revoked)
                    {
                        if (found.TbsResponseData != null && found.Signature != null
                            && found.SignatureOid != null
                            && VerifyResponse(found.TbsResponseData, found.Signature,
                                found.SignatureOid, issuer, found.ResponderCerts))
                        {
                            CacheSet(key, (true, DateTimeOffset.UtcNow + RevokedTtl));
                            return true;
                        }
                        // Unverifiable "revoked": distrust the bytes, try the
                        // next responder (documented soft-fail rationale above).
                        continue;
                    }
                    // Unknown => next responder.
                }

                CacheSet(key, (false, DateTimeOffset.UtcNow + NegCacheTtl));
                return false;
            }
            catch (OperationCanceledException) { throw; }
            catch { return false; }
        }

        static TimeSpan ClampTtl(DateTimeOffset? nextUpdate)
        {
            try
            {
                if (nextUpdate == null) return TimeSpan.FromHours(6);
                var ttl = nextUpdate.Value - DateTimeOffset.UtcNow;
                if (ttl < NegCacheTtl) return NegCacheTtl;
                if (ttl > MaxGoodTtl) return MaxGoodTtl;
                return ttl;
            }
            catch { return TimeSpan.FromHours(6); }
        }

        static string CacheKey(byte[] issuerKeyHash, BigInteger serial) =>
            Convert.ToBase64String(issuerKeyHash) + ":" + serial.ToString("X");

        // ---- AIA extraction ----

        public static List<string> GetOcspUrls(X509Certificate2 cert)
        {
            var out_ = new List<string>();
            try
            {
                if (cert == null) return out_;
                foreach (var ext in cert.Extensions)
                {
                    try
                    {
                        if (!string.Equals(ext.Oid?.Value, OidAia, StringComparison.Ordinal)) continue;
                        // RawData is normally the bare extension value; tolerate
                        // a redundant OCTET STRING wrapper either way.
                        var inner = ext.RawData;
                        try
                        {
                            var probe = new AsnReader(inner, AsnEncodingRules.DER);
                            if (probe.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
                                inner = probe.ReadOctetString();
                        }
                        catch { }
                        var seq = new AsnReader(inner, AsnEncodingRules.DER).ReadSequence();
                        while (seq.HasData)
                        {
                            var ad = seq.ReadSequence();
                            var method = ad.ReadObjectIdentifier();
                            if (!string.Equals(method, OidOcspMethod, StringComparison.Ordinal))
                            {
                                if (ad.HasData) ad.ReadEncodedValue();
                                continue;
                            }
                            if (ad.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
                            {
                                var uri = ad.ReadCharacterString(
                                    UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 6));
                                if (!string.IsNullOrWhiteSpace(uri)
                                    && uri.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                                    && !out_.Contains(uri))
                                    out_.Add(uri);
                            }
                            else if (ad.HasData) ad.ReadEncodedValue();
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return out_;
        }

        // ---- request building ----

        public static byte[] BuildRequest(X509Certificate2 leaf, X509Certificate2 issuer)
        {
            if (leaf == null) throw new ArgumentNullException(nameof(leaf));
            if (issuer == null) throw new ArgumentNullException(nameof(issuer));
            return BuildRequest(Sha1(IssuerNameDer(leaf)), Sha1(IssuerKeyBytes(issuer)), LeafSerial(leaf));
        }

        static byte[] BuildRequest(byte[] issuerNameHash, byte[] issuerKeyHash, BigInteger serial)
        {
            var w = new AsnWriter(AsnEncodingRules.DER);
            using (w.PushSequence()) // OCSPRequest
            using (w.PushSequence()) // tbsRequest
            using (w.PushSequence()) // requestList
            using (w.PushSequence()) // Request
            using (w.PushSequence()) // CertID
            {
                using (w.PushSequence()) // hashAlgorithm (SHA-1)
                {
                    w.WriteObjectIdentifier(OidSha1);
                    w.WriteNull();
                }
                w.WriteOctetString(issuerNameHash);
                w.WriteOctetString(issuerKeyHash);
                w.WriteInteger(serial);
            }
            return w.Encode();
        }

        // ---- response parsing ----

        enum OcspResponseStatus : int
        {
            Successful = 0, MalformedRequest = 1, InternalError = 2,
            TryLater = 3, SigRequired = 5, Unauthorized = 6,
        }

        // Finds the SingleResponse matching (nameHash, keyHash, serial).
        // Null = unparseable, not-successful, or no matching entry (caller
        // treats all three as "try next responder / soft-fail").
        public static OcspSingleResult? FindSingleResponse(
            byte[] responseDer, byte[] wantNameHash, byte[] wantKeyHash, BigInteger wantSerial)
        {
            try
            {
                var top = new AsnReader(responseDer, AsnEncodingRules.DER).ReadSequence();
                var status = top.ReadEnumeratedValue<OcspResponseStatus>();
                if (status != OcspResponseStatus.Successful || !top.HasData) return null;
                var respBytes = top.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                if (!string.Equals(respBytes.ReadObjectIdentifier(), OidOcspBasicResponse, StringComparison.Ordinal))
                    return null;
                var basicDer = respBytes.ReadOctetString();
                var basic = new AsnReader(basicDer, AsnEncodingRules.DER).ReadSequence();
                var tbsEncoded = basic.ReadEncodedValue().ToArray();
                var sigAlg = basic.ReadSequence();
                var sigOid = sigAlg.ReadObjectIdentifier();
                while (sigAlg.HasData) sigAlg.ReadEncodedValue();
                var sigBytes = basic.ReadBitString(out var unused);
                if (unused != 0) return null;
                var certs = new List<byte[]>();
                if (basic.HasData && basic.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    var certSeq = basic.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    while (certSeq.HasData)
                        certs.Add(certSeq.ReadEncodedValue().ToArray());
                }

                var tbs = new AsnReader(tbsEncoded, AsnEncodingRules.DER).ReadSequence();
                if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    tbs.ReadEncodedValue(); // version [0] EXPLICIT
                if (tbs.HasData) tbs.ReadEncodedValue(); // responderID
                if (tbs.HasData) tbs.ReadEncodedValue(); // producedAt
                var responses = tbs.ReadSequence();
                while (responses.HasData)
                {
                    var single = responses.ReadSequence();
                    var certId = single.ReadSequence();
                    var hashAlg = certId.ReadSequence();
                    var hashOid = hashAlg.ReadObjectIdentifier();
                    while (hashAlg.HasData) hashAlg.ReadEncodedValue();
                    var nh = certId.ReadOctetString();
                    var kh = certId.ReadOctetString();
                    var serial = certId.ReadInteger();
                    var match = string.Equals(hashOid, OidSha1, StringComparison.Ordinal)
                        && nh.AsSpan().SequenceEqual(wantNameHash)
                        && kh.AsSpan().SequenceEqual(wantKeyHash)
                        && serial == wantSerial;
                    // certStatus CHOICE.
                    var tag = single.PeekTag();
                    CertStatus st;
                    if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        single.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 0));
                        st = CertStatus.Good;
                    }
                    else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
                    {
                        var revoked = single.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                        while (revoked.HasData) revoked.ReadEncodedValue();
                        st = CertStatus.Revoked;
                    }
                    else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
                    {
                        single.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 2));
                        st = CertStatus.Unknown;
                    }
                    else return null;
                    // thisUpdate + optional nextUpdate [0] EXPLICIT.
                    if (single.HasData) single.ReadEncodedValue(); // thisUpdate
                    DateTimeOffset? nextUpdate = null;
                    if (single.HasData && single.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                    {
                        var nu = single.ReadEncodedValue().ToArray();
                        nextUpdate = ParseGeneralizedTimeInExplicit(nu);
                    }
                    if (match)
                        return new OcspSingleResult(st, tbsEncoded, sigBytes, sigOid, certs, nextUpdate);
                    // Not ours (multi-cert response): keep scanning.
                }
                return null;
            }
            catch { return null; }
        }

        static DateTimeOffset? ParseGeneralizedTimeInExplicit(byte[] explicitDer)
        {
            try
            {
                var r = new AsnReader(explicitDer, AsnEncodingRules.DER);
                var inner = r.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                var timeDer = inner.ReadEncodedValue().ToArray();
                return ParseGeneralizedTime(timeDer);
            }
            catch { return null; }
        }

        // Minimal GeneralizedTime parser (tag 0x18, "YYYYMMDDhhmmss[.f]Z").
        // Only UTC ("Z") is accepted — OCSP mandates it.
        static DateTimeOffset? ParseGeneralizedTime(byte[] der)
        {
            try
            {
                if (der == null || der.Length < 16 || der[0] != 0x18) return null;
                var pos = 1;
                int len = der[pos++];
                if ((len & 0x80) != 0)
                {
                    var n = len & 0x7F;
                    if (n <= 0 || n > 2 || pos + n > der.Length) return null;
                    len = 0;
                    for (var i = 0; i < n; i++) len = (len << 8) | der[pos++];
                }
                if (pos + len > der.Length) return null;
                var s = Encoding.ASCII.GetString(der, pos, len);
                if (!s.EndsWith("Z", StringComparison.Ordinal) || s.Length < 14) return null;
                s = s.Substring(0, s.Length - 1);
                var dot = s.IndexOf('.');
                if (dot >= 0) s = s.Substring(0, dot);
                if (s.Length != 14) return null;
                return new DateTimeOffset(
                    int.Parse(s.Substring(0, 4)), int.Parse(s.Substring(4, 2)), int.Parse(s.Substring(6, 2)),
                    int.Parse(s.Substring(8, 2)), int.Parse(s.Substring(10, 2)), int.Parse(s.Substring(12, 2)),
                    TimeSpan.Zero);
            }
            catch { return null; }
        }

        // ---- signature verification ----

        public static bool VerifyResponse(
            byte[] tbsResponseData, byte[] signature, string signatureOid,
            X509Certificate2 issuer, List<byte[]>? responderCerts)
        {
            try
            {
                if (tbsResponseData == null || signature == null || signature.Length == 0
                    || issuer == null) return false;
                if (VerifyWithCert(tbsResponseData, signature, signatureOid, issuer))
                    return true;
                // Delegated responder: a cert issued by our issuer that carries
                // the OCSPSigning EKU (when it states any EKU at all).
                if (responderCerts == null) return false;
                foreach (var der in responderCerts)
                {
                    X509Certificate2? c = null;
                    try
                    {
                        c = new X509Certificate2(der);
                        if (!string.Equals(c.Issuer, issuer.Subject, StringComparison.Ordinal))
                            continue;
                        if (HasEku(c) && !HasOcspSigningEku(c)) continue;
                        if (VerifyWithCert(tbsResponseData, signature, signatureOid, c))
                            return true;
                    }
                    catch { }
                    finally { try { c?.Dispose(); } catch { } }
                }
                return false;
            }
            catch { return false; }
        }

        static bool VerifyWithCert(byte[] tbs, byte[] sig, string oid, X509Certificate2 cert)
        {
            try
            {
                var hash = HashFromOid(oid);
                if (hash == null) return false;
                try
                {
                    using var rsa = cert.GetRSAPublicKey();
                    if (rsa != null)
                        return rsa.VerifyData(tbs, sig, hash.Value, RSASignaturePadding.Pkcs1);
                }
                catch { }
                try
                {
                    using var ec = cert.GetECDsaPublicKey();
                    if (ec != null)
                        return ec.VerifyData(tbs, sig, hash.Value);
                }
                catch { }
                return false;
            }
            catch { return false; }
        }

        static HashAlgorithmName? HashFromOid(string oid) => oid switch
        {
            "1.2.840.113549.1.1.5" => HashAlgorithmName.SHA1,
            "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
            "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
            "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
            "1.2.840.10045.4.1" => HashAlgorithmName.SHA1,
            "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256,
            "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
            "1.2.840.10045.4.3.4" => HashAlgorithmName.SHA512,
            _ => null,
        };

        static bool HasEku(X509Certificate2 c)
        {
            try
            {
                foreach (var ext in c.Extensions)
                    if (string.Equals(ext.Oid?.Value, "2.5.29.37", StringComparison.Ordinal))
                        return true;
                return false;
            }
            catch { return false; }
        }

        static bool HasOcspSigningEku(X509Certificate2 c)
        {
            try
            {
                foreach (var ext in c.Extensions)
                {
                    if (!string.Equals(ext.Oid?.Value, "2.5.29.37", StringComparison.Ordinal)) continue;
                    if (ContainsBytes(ext.RawData, OcspSigningEkuDer)) return true;
                }
                return false;
            }
            catch { return false; }
        }

        static bool ContainsBytes(byte[] hay, byte[] needle)
        {
            try
            {
                if (hay == null || needle == null || hay.Length < needle.Length) return false;
                for (var i = 0; i + needle.Length <= hay.Length; i++)
                {
                    var ok = true;
                    for (var j = 0; j < needle.Length; j++)
                        if (hay[i + j] != needle[j]) { ok = false; break; }
                    if (ok) return true;
                }
                return false;
            }
            catch { return false; }
        }

        // ---- cert DER helpers ----

        static BigInteger LeafSerial(X509Certificate2 leaf)
        {
            var le = leaf.GetSerialNumber() ?? throw new InvalidOperationException("No serial.");
            return new BigInteger(le, isUnsigned: true, isBigEndian: false);
        }

        public static byte[] LeafSerialBigEndian(X509Certificate2 leaf)
        {
            var le = (leaf.GetSerialNumber() ?? throw new InvalidOperationException("No serial.")).ToArray();
            Array.Reverse(le);
            var i = 0;
            while (i + 1 < le.Length && le[i] == 0) i++;
            return i == 0 ? le : le.Skip(i).ToArray();
        }

        // DER of the issuer Name as it appears in the leaf (== issuer subject).
        static byte[] IssuerNameDer(X509Certificate2 leaf)
        {
            var tbs = OpenTbs(leaf.RawData);
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                tbs.ReadEncodedValue(); // version [0]
            tbs.ReadEncodedValue(); // serialNumber
            tbs.ReadEncodedValue(); // signature
            return tbs.ReadEncodedValue().ToArray(); // issuer Name
        }

        // Raw public-key bytes (BIT STRING contents) of the issuer.
        static byte[] IssuerKeyBytes(X509Certificate2 issuer)
        {
            var tbs = OpenTbs(issuer.RawData);
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                tbs.ReadEncodedValue();
            tbs.ReadEncodedValue(); // serial
            tbs.ReadEncodedValue(); // signature
            tbs.ReadEncodedValue(); // issuer
            tbs.ReadEncodedValue(); // validity
            tbs.ReadEncodedValue(); // subject
            var spki = tbs.ReadEncodedValue().ToArray();
            var inner = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
            inner.ReadEncodedValue(); // algorithm
            return inner.ReadBitString(out _);
        }

        static AsnReader OpenTbs(byte[] certDer)
        {
            // AsnReader is forward-only: capture the tbsCertificate TLV, then
            // re-parse it to get a content reader positioned at its start.
            var cert = new AsnReader(certDer, AsnEncodingRules.DER).ReadSequence();
            var tbsTlv = cert.ReadEncodedValue().ToArray();
            return new AsnReader(tbsTlv, AsnEncodingRules.DER).ReadSequence();
        }

        static byte[] Sha1(byte[] data)
        {
            using var s = SHA1.Create();
            return s.ComputeHash(data);
        }

        // ---- Tor transport ----

        static async Task<byte[]?> FetchOcspAsync(
            string url, byte[] request,
            Func<string, int, CancellationToken, Task<TcpClient?>> dialTor,
            CancellationToken ct)
        {
            Uri uri;
            try
            {
                uri = new Uri(url);
                if (!uri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)) return null;
            }
            catch { return null; }
            string host;
            try { host = new IdnMapping().GetAscii(uri.Host); }
            catch { return null; }
            var port = uri.IsDefaultPort ? 80 : uri.Port;
            if (port <= 0 || port > 65535) return null;
            var path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;

            using var timeout = new CancellationTokenSource(FetchTimeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
            var lct = linked.Token;
            TcpClient? tcp = null;
            try { tcp = await dialTor(host, port, lct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch { return null; }
            if (tcp == null) return null;
            using (tcp)
            {
                NetworkStream net;
                try { net = tcp.GetStream(); }
                catch { return null; }
                var head = "POST " + path + " HTTP/1.1\r\nHost: " + host
                    + "\r\nContent-Type: application/ocsp-request\r\nContent-Length: " + request.Length
                    + "\r\nConnection: close\r\n\r\n";
                try
                {
                    await net.WriteAsync(Encoding.ASCII.GetBytes(head), lct).ConfigureAwait(false);
                    await net.WriteAsync(request, lct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch { return null; }
                return await ReadOcspHttpBodyAsync(net, lct).ConfigureAwait(false);
            }
        }

        static async Task<byte[]?> ReadOcspHttpBodyAsync(NetworkStream net, CancellationToken ct)
        {
            try
            {
                var raw = new List<byte>();
                var buf = new byte[8192];
                var headerEnd = -1;
                while (headerEnd < 0)
                {
                    int n;
                    try { n = await net.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch { return null; }
                    if (n <= 0) return null;
                    raw.AddRange(buf.Take(n));
                    if (raw.Count > MaxHttpBody + 8192) return null;
                    headerEnd = FindHeaderEnd(raw);
                }
                var headerText = Encoding.ASCII.GetString(raw.Take(headerEnd).ToArray());
                var firstLineEnd = headerText.IndexOf("\r\n", StringComparison.Ordinal);
                var statusLine = firstLineEnd >= 0 ? headerText.Substring(0, firstLineEnd) : headerText;
                if (!statusLine.Contains(" 200", StringComparison.Ordinal)) return null;
                var body = raw.Skip(headerEnd).ToArray();
                long contentLength = -1;
                var chunked = false;
                foreach (var line in headerText.Split("\r\n").Skip(1))
                {
                    var colon = line.IndexOf(':');
                    if (colon <= 0) continue;
                    var name = line.Substring(0, colon).Trim();
                    var value = line.Substring(colon + 1).Trim();
                    if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                        && long.TryParse(value, out var cl)) contentLength = cl;
                    else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                        && value.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0) chunked = true;
                }
                if (chunked) return await ReadChunkedRestAsync(net, body, ct).ConfigureAwait(false);
                if (contentLength < 0 || contentLength > MaxHttpBody) return null;
                var out_ = new List<byte>(body);
                while (out_.Count < contentLength)
                {
                    int n;
                    try { n = await net.ReadAsync(buf.AsMemory(0, buf.Length), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch { return null; }
                    if (n <= 0) return null;
                    out_.AddRange(buf.Take(n));
                    if (out_.Count > MaxHttpBody) return null;
                }
                return out_.Take((int)contentLength).ToArray();
            }
            catch (OperationCanceledException) { throw; }
            catch { return null; }
        }

        static int FindHeaderEnd(List<byte> raw)
        {
            for (var i = 0; i + 3 < raw.Count; i++)
                if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
                    return i + 4;
            return -1;
        }

        static async Task<byte[]?> ReadChunkedRestAsync(NetworkStream net, byte[] prefix, CancellationToken ct)
        {
            try
            {
                var all = new List<byte>(prefix);
                // Drain with a bound: chunked OCSP bodies are tiny.
                var tmp = new byte[8192];
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
                var lct = linked.Token;
                while (all.Count < MaxHttpBody)
                {
                    int n;
                    try { n = await net.ReadAsync(tmp.AsMemory(0, tmp.Length), lct).ConfigureAwait(false); }
                    catch { break; }
                    if (n <= 0) break;
                    all.AddRange(tmp.Take(n));
                    var decoded = TryDechunk(all.ToArray());
                    if (decoded != null) return decoded;
                }
                return TryDechunk(all.ToArray());
            }
            catch { return null; }
        }

        static byte[]? TryDechunk(byte[] data)
        {
            try
            {
                var out_ = new List<byte>();
                var pos = 0;
                while (true)
                {
                    var eol = IndexOfCrlf(data, pos);
                    if (eol < 0) return null; // need more data
                    var line = Encoding.ASCII.GetString(data, pos, eol - pos);
                    var semi = line.IndexOf(';');
                    if (!int.TryParse((semi >= 0 ? line.Substring(0, semi) : line).Trim(),
                            System.Globalization.NumberStyles.HexNumber,
                            System.Globalization.CultureInfo.InvariantCulture, out var size) || size < 0)
                        return null;
                    pos = eol + 2;
                    if (size == 0) return out_.ToArray(); // ignore trailers
                    if (pos + size + 2 > data.Length) return null; // need more
                    out_.AddRange(data.Skip(pos).Take(size));
                    if (out_.Count > MaxHttpBody) return null;
                    pos += size;
                    if (data[pos] != '\r' || data[pos + 1] != '\n') return null;
                    pos += 2;
                }
            }
            catch { return null; }
        }

        static int IndexOfCrlf(byte[] data, int from)
        {
            for (var i = from; i + 1 < data.Length; i++)
                if (data[i] == '\r' && data[i + 1] == '\n') return i;
            return -1;
        }
    }
}
