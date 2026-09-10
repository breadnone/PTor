using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace PTor
{

    // Verifies expert-bundle .asc signatures against the pinned Tor signing
    // key. File ships with our release (same trust as our exe); the PIN in
    // code is the anchor, so a swapped key file fails closed. Rotation ships
    // with an app update. Pin cross-check:
    //   https://support.torproject.org/tbb/how-to-verify-signature/
    public static class TorReleaseSigner
    {
        public const string PinnedFingerprint = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";
        public const string KeyFileName = "TorSigningKey.asc";
        // Keyserver fallback for a missing key file; pin-checked, fail closed.
        const string KeyserverUrl =
            "https://keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

        static readonly System.Net.Http.HttpClient _keyHttp = new System.Net.Http.HttpClient();

        public static void VerifyDetached(byte[] data, byte[] armoredSignature, string keyRingFile)
        {
            VerifyDetached(data, armoredSignature, LoadKeyRing(keyRingFile), PinnedFingerprint);
        }

        internal static string LoadKeyRing(string keyRingFile)
        {
            try
            {
                var armor = File.ReadAllText(keyRingFile);
                if (!string.IsNullOrWhiteSpace(armor) && RingHasPinnedPrimary(armor, PinnedFingerprint))
                    return armor;
            }
            catch { }
            // Missing/wrong file: fetch and pin-check (fail closed).
            try
            {
                using var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(30));
                var armor = _keyHttp.GetStringAsync(KeyserverUrl, cts.Token).GetAwaiter().GetResult();
                if (!string.IsNullOrWhiteSpace(armor) && RingHasPinnedPrimary(armor, PinnedFingerprint))
                    return armor;
            }
            catch { }
            throw new InvalidOperationException(
                "PGP verify: no usable signing key (shipped " + KeyFileName +
                " missing/wrong and keyserver fallback failed) — refusing to install.");
        }

        internal static bool RingHasPinnedPrimary(string armor, string pinned)
        {
            try
            {
                foreach (var fp in RingPrimaryFingerprints(armor))
                    if (fp.Equals(pinned, StringComparison.OrdinalIgnoreCase))
                        return true;
                return false;
            }
            catch { return false; }
        }

        internal static void VerifyDetached(byte[] data, byte[] armoredSignature, string armoredKeyRing, string pinnedFingerprint)
        {
            if (data == null || data.Length == 0)
                throw new InvalidOperationException("PGP verify: no data to verify — refusing to install.");
            if (armoredSignature == null || armoredSignature.Length == 0 || armoredSignature.Length > 1024 * 1024)
                throw new InvalidOperationException("PGP verify: signature missing or absurdly sized — refusing to install.");

            PgpSignatureList sigs;
            try
            {
                var fact = new PgpObjectFactory(PgpUtilities.GetDecoderStream(new MemoryStream(armoredSignature)));
                var o = fact.NextPgpObject();
                if (o is PgpCompressedData cd)
                    o = new PgpObjectFactory(cd.GetDataStream()).NextPgpObject();
                sigs = o as PgpSignatureList
                    ?? throw new InvalidOperationException("PGP verify: no signature packet in .asc — refusing to install.");
            }
            catch (InvalidOperationException) { throw; }
            catch (Exception ex)
            {
                throw new InvalidOperationException("PGP verify: unreadable signature: " + ex.Message, ex);
            }

            PgpPublicKeyRingBundle rings;
            try
            {
                rings = new PgpPublicKeyRingBundle(
                    PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(armoredKeyRing))));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("PGP verify: unreadable keyring: " + ex.Message, ex);
            }

            var notes = new List<string>();
            for (var si = 0; si < sigs.Count; si++)
            {
                var sig = sigs[si];
                PgpPublicKey? issuer;
                try { issuer = FindIssuer(rings, sig.KeyId, pinnedFingerprint); }
                catch (Exception ex) { notes.Add("issuer lookup: " + ex.Message); continue; }
                if (issuer == null) { notes.Add($"skipped signature from unknown key {sig.KeyId:X16}"); continue; }
                if (!IsAllowedHash(sig.HashAlgorithm))
                    throw new InvalidOperationException(
                        $"PGP verify: rejecting weak hash algorithm {sig.HashAlgorithm} — refusing to install.");
                try
                {
                    sig.InitVerify(issuer);
                    const int Chunk = 81920;
                    for (var off = 0; off < data.Length; off += Chunk)
                        sig.Update(data, off, Math.Min(Chunk, data.Length - off));
                    if (sig.Verify()) return;
                    notes.Add($"bad signature from key {sig.KeyId:X16}");
                }
                catch (InvalidOperationException) { throw; }
                catch (Exception ex) { notes.Add(ex.GetType().Name + ": " + ex.Message); }
            }
            throw new InvalidOperationException(
                "PGP signature verification failed (" + string.Join("; ", notes) + ") — refusing to install.");
        }

        static PgpPublicKey? FindIssuer(PgpPublicKeyRingBundle rings, long keyId, string pinnedFingerprint)
        {
            foreach (PgpPublicKeyRing ring in rings.GetKeyRings())
            {
                PgpPublicKey? primary;
                try { primary = ring.GetPublicKey(); }
                catch { continue; }
                if (primary == null) continue;
                string fp;
                try { fp = BitConverter.ToString(primary.GetFingerprint()).Replace("-", ""); }
                catch { continue; }
                if (!fp.Equals(pinnedFingerprint, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var issuer = ring.GetPublicKey(keyId);
                    if (issuer != null) return issuer;
                }
                catch { }
            }
            return null;
        }

        static bool IsAllowedHash(HashAlgorithmTag algo) =>
            algo is HashAlgorithmTag.Sha224 or HashAlgorithmTag.Sha256
                or HashAlgorithmTag.Sha384 or HashAlgorithmTag.Sha512
               ;

        internal static List<string> RingPrimaryFingerprints(string armoredKeyRing)
        {
            var out_ = new List<string>();
            var rings = new PgpPublicKeyRingBundle(
                PgpUtilities.GetDecoderStream(new MemoryStream(Encoding.ASCII.GetBytes(armoredKeyRing))));
            foreach (PgpPublicKeyRing ring in rings.GetKeyRings())
            {
                try
                {
                    var primary = ring.GetPublicKey();
                    if (primary != null)
                        out_.Add(BitConverter.ToString(primary.GetFingerprint()).Replace("-", ""));
                }
                catch { }
            }
            return out_;
        }
    }
}
