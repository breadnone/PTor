using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PTor
{
    // Local CA for HTTPS inspection. FREE: self-signed, generated on this PC
    // with the platform crypto stack (no purchased certs, no ACME/Let's
    // Encrypt — public CAs must never issue MITM certs by design).
    //
    // Security model (read before touching):
    // - The CA private key lives ONLY under %AppData%\PTor\mitm (user-profile
    //   files) and is NEVER transmitted, logged, or added to any trust store
    //   (only the PUBLIC cert is installed).
    // - Origins are still validated fail-closed through Tor (chain + expiry
    //   + hostname, plus OCSP revocation fetched THROUGH Tor — never direct,
    //   so no destination leaks; see MitmOcsp).
    // - Leaf certs are per-host, short-lived (90d), random 128-bit serials,
    //   serverAuth-only, CA:false, cached per process (never written to disk).
    // - All leaves share ONE per-install RSA key in the user's CNG software
    //   key store (non-exportable). This is REQUIRED, not just an optimization:
    //   Windows SChannel refuses TLS server authentication with ephemeral keys
    //   ("the platform does not support ephemeral keys"), so per-leaf
    //   RSA.Create() keys cannot serve handshakes. One stable key also avoids
    //   accumulating a persisted container per host. Impact of compromise is
    //   local-only (this user's MITM leaves).
    public sealed class MitmCaManager
    {
        const string CaSubject = "CN=PTor Local MITM CA, O=PTor Local";
        const int CaValidityYears = 10;
        const int LeafValidityDays = 90;
        const int LeafCacheCap = 256;

        readonly object _gate = new();
        readonly ConcurrentDictionary<string, X509Certificate2> _leaves = new(StringComparer.OrdinalIgnoreCase);
        X509Certificate2? _ca;

        // Shared per-install leaf key (see class notes: SChannel mandates a
        // persisted key for server auth). Never disposed except on regen.
        const string LeafKeyName = "PTorMitmLeaf";
        readonly object _leafKeyGate = new();
        RSA? _leafKey;

        RSA GetLeafKey()
        {
            lock (_leafKeyGate)
            {
                if (_leafKey != null) return _leafKey;
                System.Security.Cryptography.CngKey cng;
                try
                {
                    cng = System.Security.Cryptography.CngKey.Open(LeafKeyName);
                }
                catch
                {
                    var parms = new System.Security.Cryptography.CngKeyCreationParameters
                    {
                        ExportPolicy = System.Security.Cryptography.CngExportPolicies.None,
                        KeyUsage = System.Security.Cryptography.CngKeyUsages.AllUsages,
                        Provider = System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    };
                    parms.Parameters.Add(new System.Security.Cryptography.CngProperty(
                        "Length", BitConverter.GetBytes(2048),
                        System.Security.Cryptography.CngPropertyOptions.None));
                    cng = System.Security.Cryptography.CngKey.Create(
                        System.Security.Cryptography.CngAlgorithm.Rsa, LeafKeyName, parms);
                }
                _leafKey = new RSACng(cng);
                return _leafKey;
            }
        }

        void DeleteLeafKey()
        {
            lock (_leafKeyGate)
            {
                try { _leafKey?.Dispose(); } catch { }
                _leafKey = null;
                try
                {
                    using var k = System.Security.Cryptography.CngKey.Open(
                        LeafKeyName,
                        System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider);
                    k.Delete();
                }
                catch { }
            }
        }

        static string MitmDir()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PTor", "mitm");
            Directory.CreateDirectory(dir);
            try { ApplyUserOnlyAclDir(dir); } catch { }
            return dir;
        }

        static string CaPfxPath() => Path.Combine(MitmDir(), "ca.pfx");
        static string CaPwdPath() => Path.Combine(MitmDir(), "ca.pwd");
        static string CaCrtPath() => Path.Combine(MitmDir(), "ca.crt");

        public bool CaExists()
        {
            try { return File.Exists(CaPfxPath()) && File.Exists(CaPwdPath()); }
            catch { return false; }
        }

        public bool IsUsable()
        {
            try { EnsureCa(); return true; }
            catch { return false; }
        }

        public X509Certificate2 EnsureCa()
        {
            lock (_gate)
            {
                if (_ca != null && _ca.HasPrivateKey) return _ca;
                try { _ca?.Dispose(); } catch { }
                _ca = null;
                if (TryLoadCa(out var loaded) && loaded != null) { _ca = loaded; return _ca; }
                _ca = CreateAndPersistCa();
                return _ca;
            }
        }

        bool TryLoadCa(out X509Certificate2? ca)
        {
            ca = null;
            try
            {
                var pfx = CaPfxPath();
                var pwdFile = CaPwdPath();
                if (!File.Exists(pfx) || !File.Exists(pwdFile)) return false;
                // Capped: the password is ~44 chars; a bloated file is corrupt,
                // not a password (regenerate below instead of slurping it).
                var pwd = (SafeFiles.ReadAllTextCapped(pwdFile, 4096) ?? "").Trim();
                if (string.IsNullOrEmpty(pwd)) return false;
                var bytes = SafeFiles.ReadAllBytesCapped(pfx, 1024 * 1024);
                if (bytes == null || bytes.Length == 0) return false;
                ca = X509CertificateLoader.LoadPkcs12(bytes, pwd,
                    X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
                if (ca == null || !ca.HasPrivateKey) { try { ca?.Dispose(); } catch { } ca = null; return false; }
                // Basic sanity: still valid and actually a CA.
                if (DateTimeOffset.UtcNow > ca.NotAfter || DateTimeOffset.UtcNow < ca.NotBefore)
                    return false;
                var bc = ca.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
                if (bc == null || !bc.CertificateAuthority) return false;
                return true;
            }
            catch { try { ca?.Dispose(); } catch { } ca = null; return false; }
        }

        X509Certificate2 CreateAndPersistCa()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                new X500DistinguishedName(CaSubject),
                rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
            // No EKU on a root: unconstrained CA within its (local) scope.
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            var ca = req.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(CaValidityYears));
            var pwd = RandomPassword(32);
            var pfx = ca.Export(X509ContentType.Pfx, pwd);
            try
            {
                // Atomic each, then verified by reload below: a crash between
                // the three writes can only leave a mismatched pair, which
                // TryLoadCa rejects (regenerated on next EnsureCa) — never a
                // half-key that loads wrong.
                if (!SafeFiles.WriteAllBytesAtomic(CaPfxPath(), pfx)) throw new IOException("CA store unwritable.");
                if (!SafeFiles.WriteAllTextAtomic(CaPwdPath(), pwd)) throw new IOException("CA store unwritable.");
                if (!SafeFiles.WriteAllBytesAtomic(CaCrtPath(), ca.Export(X509ContentType.Cert))) throw new IOException("CA store unwritable.");
                try { ApplyUserOnlyAclFile(CaPfxPath()); } catch { }
                try { ApplyUserOnlyAclFile(CaPwdPath()); } catch { }
            }
            catch { throw; }
            finally { try { ca.Dispose(); } catch { } }
            if (!TryLoadCa(out var reloaded) || reloaded == null)
                throw new InvalidOperationException("CA was generated but could not be reloaded (mitm store unreadable).");
            return reloaded;
        }

        static string RandomPassword(int len)
        {
            const string alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789-_.";
            var buf = new byte[len];
            RandomNumberGenerator.Fill(buf);
            var chars = new char[len];
            for (var i = 0; i < len; i++) chars[i] = alphabet[buf[i] % alphabet.Length];
            return new string(chars);
        }

        // Normalize + validate a CONNECT host for leaf issuance. Returns the
        // SAN-ready form (punycode for DNS, compressed for IP). Throws on
        // anything that must never go on a certificate.
        public static string NormalizeHostForCert(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                throw new ArgumentException("Empty hostname.", nameof(host));
            var h = host.Trim().Trim('[', ']').Trim().Trim('.').Trim();
            if (h.Length == 0 || h.Length > 253)
                throw new ArgumentException("Hostname length out of range.");
            if (IPAddress.TryParse(h, out var ip))
                return ip.ToString();
            if (h.Contains('/') || h.Contains(':') || h.Contains('@') || h.Contains('*')
                || h.Any(char.IsWhiteSpace) || h.Any(c => c < 0x20))
                throw new ArgumentException("Illegal characters in hostname.");
            string ascii;
            try { ascii = new IdnMapping().GetAscii(h.ToLowerInvariant()); }
            catch (Exception ex) { throw new ArgumentException("Hostname is not valid IDN: " + ex.Message); }
            if (ascii.Length == 0 || ascii.Length > 253 || !ascii.Contains('.') && ascii.Length > 63)
            {
                // Single-label names (e.g. "localhost", intranet hosts) are
                // still issuable — browsers accept them from a trusted root.
            }
            var labels = ascii.Split('.');
            foreach (var label in labels)
            {
                if (label.Length == 0 || label.Length > 63)
                    throw new ArgumentException("Bad hostname label length.");
                if (label.StartsWith("-", StringComparison.Ordinal) || label.EndsWith("-", StringComparison.Ordinal))
                    throw new ArgumentException("Bad hostname label.");
                foreach (var c in label)
                {
                    var ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
                    if (!ok) throw new ArgumentException($"Illegal hostname character '{c}'.");
                }
            }
            return ascii;
        }

        public X509Certificate2 GetLeafCertificate(string host)
        {
            var norm = NormalizeHostForCert(host);
            if (_leaves.TryGetValue(norm, out var cached))
            {
                try
                {
                    if (DateTimeOffset.UtcNow < cached.NotAfter.AddDays(-1)) return cached;
                    _leaves.TryRemove(norm, out _);
                    try { cached.Dispose(); } catch { }
                }
                catch { }
            }
            lock (_gate)
            {
                if (_leaves.TryGetValue(norm, out cached)) return cached;
                var ca = EnsureCa();
                var leaf = CreateLeaf(ca, norm);
                if (_leaves.Count >= LeafCacheCap)
                {
                    try
                    {
                        var first = _leaves.Keys.FirstOrDefault();
                        if (first != null && _leaves.TryRemove(first, out var old))
                            try { old.Dispose(); } catch { }
                    }
                    catch { }
                }
                _leaves[norm] = leaf;
                return leaf;
            }
        }

        X509Certificate2 CreateLeaf(X509Certificate2 ca, string normHost)
        {
            bool isIp = IPAddress.TryParse(normHost, out var ip);
            var cn = normHost.Length > 64 ? normHost.Substring(0, 64) : normHost;
            var rsa = GetLeafKey(); // shared persisted key (never disposed here)
            var req = new CertificateRequest(
                new X500DistinguishedName("CN=" + EscapeCn(cn)),
                rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true));
            var san = new SubjectAlternativeNameBuilder();
            if (isIp && ip != null) san.AddIpAddress(ip);
            else san.AddDnsName(normHost);
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            var serial = new byte[16];
            RandomNumberGenerator.Fill(serial);
            serial[0] &= 0x7F; // positive
            var notAfter = DateTimeOffset.UtcNow.AddDays(LeafValidityDays);
            try
            {
                if (notAfter >= ca.NotAfter) notAfter = ca.NotAfter.AddDays(-1);
            }
            catch { }
            var cert = req.Create(ca,
                DateTimeOffset.UtcNow.AddDays(-1), notAfter, serial);
            if (!cert.HasPrivateKey)
            {
                // Framework builds differ: attach the request key if needed.
                var withKey = cert.CopyWithPrivateKey(rsa);
                try { cert.Dispose(); } catch { }
                cert = withKey;
            }
            return cert;
        }

        static string EscapeCn(string cn)
        {
            // X500 DN special chars must be escaped.
            return cn.Replace("\\", "\\\\").Replace(",", "\\,").Replace("+", "\\+")
                .Replace("\"", "\\\"").Replace("<", "\\<").Replace(">", "\\>")
                .Replace(";", "\\;");
        }

        public string CaFingerprintSha256()
        {
            try
            {
                var ca = EnsureCa();
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(ca.RawData);
                return string.Join(":", hash.Select(b => b.ToString("X2")));
            }
            catch { return "(unavailable)"; }
        }

        public string CaPublicPemPath() => CaCrtPath();

        public bool IsCaInstalled()
        {
            try
            {
                var ca = EnsureCa();
                if (IsThumbInStore(ca.Thumbprint, StoreLocation.CurrentUser)) return true;
                try
                {
                    if (AdminHelper.IsAdministrator()
                        && IsThumbInStore(ca.Thumbprint, StoreLocation.LocalMachine))
                        return true;
                }
                catch { }
                return false;
            }
            catch { return false; }
        }

        static bool IsThumbInStore(string thumbprint, StoreLocation location)
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
            }
            catch { return false; }
        }

        public bool IsCaInstalledInMachineStore()
        {
            try
            {
                var ca = EnsureCa();
                return IsThumbInStore(ca.Thumbprint, StoreLocation.LocalMachine);
            }
            catch { return false; }
        }

        static bool AddToStore(X509Certificate2 ca, StoreLocation location)
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadWrite);
                if (store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, false).Count > 0)
                    return true; // already there
                var pub = X509CertificateLoader.LoadCertificate(ca.Export(X509ContentType.Cert));
                try { store.Add(pub); return true; }
                catch { return false; }
                finally { try { pub.Dispose(); } catch { } }
            }
            catch { return false; }
        }

        static bool RemoveFromStore(string thumbprint, StoreLocation location)
        {
            var removed = false;
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadWrite);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                foreach (var c in found) { try { store.Remove(c); removed = true; } catch { } finally { try { c.Dispose(); } catch { } } }
            }
            catch { }
            return removed;
        }

        // Installs the PUBLIC cert into CurrentUser\Root (no admin needed),
        // plus LocalMachine\Root when elevated so every Windows user on this
        // PC trusts it (fixes the old "other users aren't covered" gap).
        // Also auto-enables Firefox/Thunderbird trust (they ignore the
        // Windows store by default) — no manual about:config or ca.crt
        // import needed. Windows may show a one-time trust confirmation —
        // declining surfaces here as a failure (fail-closed).
        public string InstallCa()
        {
            var ca = EnsureCa();
            bool user;
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                try { store.Open(OpenFlags.ReadWrite); }
                catch (Exception ex) { throw new InvalidOperationException("Could not open the user trust store: " + ex.Message, ex); }
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, ca.Thumbprint, false);
                if (found.Count == 0)
                {
                    var pub = X509CertificateLoader.LoadCertificate(ca.Export(X509ContentType.Cert));
                    try { store.Add(pub); }
                    catch (Exception ex) { throw new InvalidOperationException("CA install declined or failed: " + ex.Message, ex); }
                    finally { try { pub.Dispose(); } catch { } }
                }
                user = true;
            }
            catch (InvalidOperationException) { throw; }
            catch (Exception ex) { throw new InvalidOperationException("CA install declined or failed: " + ex.Message, ex); }

            var machineNote = "";
            try
            {
                if (AdminHelper.IsAdministrator())
                    machineNote = AddToStore(ca, StoreLocation.LocalMachine)
                        ? " + LocalMachine\\Root (all users)"
                        : " (LocalMachine\\Root install failed — current user only)";
            }
            catch { }

            string fxNote;
            try { fxNote = FirefoxTrust.EnableEnterpriseRoots(); }
            catch (Exception ex) { fxNote = "Firefox auto-config skipped (" + ex.Message + ")"; }
            _ = user;
            return "PTor CA installed into CurrentUser\\Root" + machineNote + " — browsers trusting the Windows store will accept inspected HTTPS. " + fxNote + ".";
        }

        public string RemoveCa()
        {
            try
            {
                if (!CaExists()) return "No local CA exists — nothing to remove.";
                var ca = EnsureCa();
                var userGone = RemoveFromStore(ca.Thumbprint, StoreLocation.CurrentUser);
                var machineGone = false;
                try
                {
                    if (AdminHelper.IsAdministrator())
                        machineGone = RemoveFromStore(ca.Thumbprint, StoreLocation.LocalMachine);
                }
                catch { }
                string fxNote;
                try { fxNote = FirefoxTrust.DisableEnterpriseRoots(); }
                catch (Exception ex) { fxNote = "Firefox cleanup skipped (" + ex.Message + ")"; }
                return (userGone || machineGone)
                    ? "PTor CA removed from " + (machineGone && userGone ? "user + machine" : machineGone ? "LocalMachine\\Root" : "CurrentUser\\Root")
                        + " trust. Inspection stops trusting until reinstalled. " + fxNote + "."
                    : "PTor CA was not in CurrentUser\\Root (already gone or never installed). Key files kept for next install. " + fxNote + ".";
            }
            catch (Exception ex) { return "CA removal issue: " + ex.Message; }
        }

        // Uninstall-time cleanup (also callable standalone): removes PTor CA
        // trust for the CURRENT user only + deletes the persisted leaf key.
        // Folder-independent (works after %AppData%\PTor is gone) by matching
        // our exact CA subject. Firefox auto-config lines for this user go
        // too. For every user on the box see RemoveTrustForAllUsers (admin).
        public static string RemoveTrustAndLeafKeyForCurrentUser()
        {
            var parts = new List<string>();
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                var removed = 0;
                foreach (var cert in store.Certificates.OfType<X509Certificate2>().ToList())
                {
                    bool ours = false;
                    try
                    {
                        ours = string.Equals(cert.Subject, "CN=PTor Local MITM CA, O=PTor Local",
                            StringComparison.OrdinalIgnoreCase);
                    }
                    catch { }
                    if (!ours) continue;
                    try { store.Remove(cert); removed++; } catch { }
                    try { cert.Dispose(); } catch { }
                }
                parts.Add(removed > 0
                    ? $"removed {removed} PTor CA cert(s) from this user's Trusted Root"
                    : "no PTor CA in this user's Trusted Root");
            }
            catch (Exception ex) { parts.Add("trust cleanup failed (" + ex.Message + ")"); }
            try
            {
                using var k = System.Security.Cryptography.CngKey.Open(
                    LeafKeyName,
                    System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider);
                k.Delete();
                parts.Add("deleted the per-install leaf key");
            }
            catch { parts.Add("no persisted leaf key found"); }
            try { parts.Add(FirefoxTrust.DisableEnterpriseRoots()); }
            catch (Exception ex) { parts.Add("Firefox cleanup skipped (" + ex.Message + ")"); }
            return "MITM leftovers: " + string.Join("; ", parts) + ".";
        }

        // Admin uninstall path: every reachable trust location. Current-user
        // store + LocalMachine store (both matched by our exact CA subject so
        // a regenerated CA from another install is never touched) + all
        // users' Firefox auto-config lines + the leaf key.
        public static string RemoveTrustForAllUsers()
        {
            var parts = new List<string>();
            try { parts.Add(RemoveTrustAndLeafKeyForCurrentUser()); }
            catch (Exception ex) { parts.Add("current-user cleanup failed (" + ex.Message + ")"); }
            try
            {
                using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                var removed = 0;
                foreach (var cert in store.Certificates.OfType<X509Certificate2>().ToList())
                {
                    bool ours = false;
                    try
                    {
                        ours = string.Equals(cert.Subject, "CN=PTor Local MITM CA, O=PTor Local",
                            StringComparison.OrdinalIgnoreCase);
                    }
                    catch { }
                    if (!ours) continue;
                    try { store.Remove(cert); removed++; } catch { }
                    try { cert.Dispose(); } catch { }
                }
                parts.Add(removed > 0
                    ? $"removed {removed} PTor CA cert(s) from LocalMachine Trusted Root"
                    : "no PTor CA in LocalMachine Trusted Root");
            }
            catch (Exception ex) { parts.Add("machine trust cleanup failed (" + ex.Message + ")"); }
            try { parts.Add(FirefoxTrust.DisableEnterpriseRootsAllUsers()); }
            catch (Exception ex) { parts.Add("all-users Firefox cleanup skipped (" + ex.Message + ")"); }
            return string.Join(" ", parts.ToArray());
        }

        public string RegenerateCa()
        {
            lock (_gate)
            {
                string? oldThumb = null;
                try { oldThumb = _ca?.Thumbprint ?? EnsureCa().Thumbprint; } catch { }
                try { _ca?.Dispose(); } catch { }
                _ca = null;
                foreach (var kv in _leaves) { try { kv.Value.Dispose(); } catch { } }
                _leaves.Clear();
                try { if (File.Exists(CaPfxPath())) File.Delete(CaPfxPath()); } catch { }
                try { if (File.Exists(CaPwdPath())) File.Delete(CaPwdPath()); } catch { }
                try { if (File.Exists(CaCrtPath())) File.Delete(CaCrtPath()); } catch { }
                try { DeleteLeafKey(); } catch { }
                var fresh = EnsureCa();
                var cleaned = false;
                if (!string.IsNullOrEmpty(oldThumb) && !string.Equals(oldThumb, fresh.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
                        store.Open(OpenFlags.ReadWrite);
                        var found = store.Certificates.Find(X509FindType.FindByThumbprint, oldThumb, false);
                        foreach (var c in found) { try { store.Remove(c); cleaned = true; } catch { } finally { try { c.Dispose(); } catch { } } }
                    }
                    catch { }
                    // The old CA may also live in LocalMachine (installed
                    // while elevated) — same thumbprint, same cleanup.
                    try
                    {
                        if (AdminHelper.IsAdministrator())
                            cleaned |= RemoveFromStore(oldThumb, StoreLocation.LocalMachine);
                    }
                    catch { }
                }
                return "New local CA generated (fingerprint " + CaFingerprintSha256() + "). "
                    + (cleaned ? "Old CA removed from trust. " : "If the old CA was trusted, remove it manually. ")
                    + "Re-install the CA to keep inspecting HTTPS.";
            }
        }

        // The mitm dir lives under the user's own profile (%AppData%), whose
        // default ACLs already scope access to this user + SYSTEM + admins
        // (admins can read anything on the box regardless). Explicit ACL
        // rewriting is deliberately avoided: the static SetAccessControl APIs
        // don't exist on modern .NET and instance ACL edits risk locking the
        // user out on failure. These stay as documented no-ops.
        static void ApplyUserOnlyAclDir(string dir) { try { _ = dir; } catch { } }

        static void ApplyUserOnlyAclFile(string path) { try { _ = path; } catch { } }
    }
}
