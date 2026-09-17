using System;
using System.Formats.Tar;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace PTor
{
    public class UpdateProgress
    {
        public string Stage { get; init; } = "";
        public double? PercentOfStage { get; init; }
    }

    public class TorUpdater
    {
        const string DownloadPageUrl = "https://www.torproject.org/download/tor/";

        static readonly Regex WindowsX64StableRegex = new(
            @"href=""(https://archive\.torproject\.org/tor-package-archive/torbrowser/[^""]*tor-expert-bundle-windows-x86_64-[^""]*\.tar\.gz)""",
            RegexOptions.IgnoreCase);

        readonly string _toolsDir;
        string _userAgent = "PTor-Updater/1.0";

        // Update traffic via Tor while routing is up (torproject.org may be censored).
        public bool UseTorRoute { get; set; }
        public int TorSocksPort { get; set; } = 9050;

        public TorUpdater(string appBaseDir)
        {
            _toolsDir = Path.Combine(appBaseDir, "tools");
        }

        HttpClient CreateClient()
        {
            SocketsHttpHandler handler;
            if (UseTorRoute)
            {
                handler = new SocketsHttpHandler
                {
                    Proxy = new System.Net.WebProxy($"socks5://127.0.0.1:{TorSocksPort}"),
                    UseProxy = true,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2)
                };
            }
            else
            {
                handler = new SocketsHttpHandler { UseProxy = false };
            }
            var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(120) };
            try
            {
                if (!string.IsNullOrWhiteSpace(_userAgent))
                    client.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent.Trim());
            }
            catch { }
            return client;
        }

        public bool SetUserAgent(string? userAgent)
        {
            if (string.IsNullOrWhiteSpace(userAgent))
            {
                _userAgent = "";
                return true;
            }
            var v = userAgent.Trim();
            using (var probe = new HttpClient())
            {
                if (!probe.DefaultRequestHeaders.UserAgent.TryParseAdd(v))
                    return false;
            }
            _userAgent = v;
            return true;
        }

        public async Task<(string url, string version)> GetLatestStableUrlAsync()
        {
            using var client = CreateClient();
            var html = await client.GetStringAsync(DownloadPageUrl);
            var match = WindowsX64StableRegex.Match(html);
            if (!match.Success)
                throw new InvalidOperationException(
                    "Could not find a Windows x86_64 Expert Bundle link on the download page. " +
                    "The page layout may have changed.");
            var url = match.Value.Substring("href=\"".Length).TrimEnd('"');
            var versionMatch = Regex.Match(url, @"windows-x86_64-([\d.]+[a-z0-9]*)\.tar\.gz$", RegexOptions.IgnoreCase);
            return (url, versionMatch.Success ? versionMatch.Groups[1].Value : "unknown");
        }

        public async Task InstallAsync(string url, IProgress<UpdateProgress>? progress = null, string? bundleVersion = null)
        {
            ValidateUrl(url);
            Directory.CreateDirectory(_toolsDir);
            var tempTarGz = Path.Combine(Path.GetTempPath(), $"tor-expert-bundle-{Guid.NewGuid():N}.tar.gz");
            var tempExtractDir = Path.Combine(Path.GetTempPath(), $"tor-expert-extract-{Guid.NewGuid():N}");
            var destTorDir = Path.Combine(_toolsDir, "Tor");
            string? backupDir = null;

            try
            {
                progress?.Report(new UpdateProgress { Stage = "Downloading Tor Expert Bundle..." });
                await DownloadAsync(url, tempTarGz, progress);
                await VerifyChecksumAsync(url, tempTarGz, progress);
                await VerifySignatureAsync(url, tempTarGz, progress);

                progress?.Report(new UpdateProgress { Stage = "Extracting..." });
                Directory.CreateDirectory(tempExtractDir);
                await ExtractTarGzAsync(tempTarGz, tempExtractDir);

                var sourceTorDir = Path.Combine(tempExtractDir, "Tor");
                if (!Directory.Exists(sourceTorDir)) sourceTorDir = tempExtractDir;
                if (!File.Exists(Path.Combine(sourceTorDir, "tor.exe")))
                    throw new InvalidOperationException(
                        "Downloaded archive has an unexpected layout (tor.exe missing) — current install untouched.");

                progress?.Report(new UpdateProgress { Stage = "Installing new version..." });
                WriteSentinel(url);
                if (Directory.Exists(destTorDir))
                {
                    backupDir = Path.Combine(_toolsDir, $"Tor_backup_{DateTime.Now:yyyyMMdd_HHmmss}");
                    Directory.Move(destTorDir, backupDir);
                }
                try
                {
                    CopyDirectory(sourceTorDir, destTorDir);
                }
                catch (Exception ex)
                {
                    throw RestoreBackup(destTorDir, backupDir, "Copy failed: " + ex.Message);
                }
                if (!File.Exists(Path.Combine(destTorDir, "tor.exe")))
                    throw RestoreBackup(destTorDir, backupDir, "Installed copy incomplete (tor.exe missing after copy).");

                // Upstream bundles ship their own pluggable_transports — with
                // the snowflake→lyrebird mis-mapping still in it — and no
                // snowflake-client.exe at all. The wholesale dir replace above
                // would wipe PTor's fixed pt_config.json and any
                // user-installed snowflake-client.exe, silently re-breaking
                // Snowflake on every Tor update. Restore PTor's files over the
                // fresh bundle: our pt_config.json (fixed plugin mapping) and
                // any helper binary upstream doesn't ship (never the reverse:
                // upstream's lyrebird/conjure still update normally).
                try
                {
                    PreservePluggableTransports(backupDir, destTorDir);
                }
                catch (Exception ex)
                {
                    throw RestoreBackup(destTorDir, backupDir, "Transport preservation failed: " + ex.Message);
                }
                if (!File.Exists(Path.Combine(destTorDir, "tor.exe")))
                    throw RestoreBackup(destTorDir, backupDir, "Installed copy incomplete (tor.exe missing after preserve).");

                ClearSentinel();
                PruneBackups(backupDir);
                if (!string.IsNullOrWhiteSpace(bundleVersion))
                    WriteInstalledBundleVersion(bundleVersion.Trim());
                progress?.Report(new UpdateProgress { Stage = "Done." });
            }
            finally
            {
                TryDelete(tempTarGz);
                TryDeleteDir(tempExtractDir);
            }
        }

        static void ValidateUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
                || uri.Scheme != Uri.UriSchemeHttps
                || !uri.Host.Equals("archive.torproject.org", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Refusing to download: unexpected URL " + url);
        }

        async Task DownloadAsync(string url, string destPath, IProgress<UpdateProgress>? progress)
        {
            using var client = CreateClient();
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength;
            RequireDiskSpace(destPath, totalBytes);

            await using var httpStream = await response.Content.ReadAsStreamAsync();
            await using var fileStream = File.Create(destPath);

            var buffer = new byte[81920];
            long readSoFar = 0;
            while (true)
            {
                // HttpClient.Timeout skips body reads under ResponseHeadersRead: per-chunk deadline instead.
                int read;
                using (var chunkCts = new CancellationTokenSource(TimeSpan.FromSeconds(60)))
                {
                    try { read = await httpStream.ReadAsync(buffer, chunkCts.Token); }
                    catch (OperationCanceledException)
                    {
                        throw new IOException("Download stalled (no bytes for 60 seconds) — retry. Current install untouched.");
                    }
                }
                if (read <= 0) break;
                await fileStream.WriteAsync(buffer.AsMemory(0, read));
                readSoFar += read;
                // totalBytes <= 0 (missing, zero, or hostile Content-Length)
                // is treated as unknown: no percent (indeterminate UI) and no
                // truncation check. A zero divisor here would yield Infinity
                // (readSoFar > 0) or NaN (0/0), which poisons the progress bar
                // (Value = NaN throws) and prints "NaN%"/"∞%".
                if (totalBytes.HasValue && totalBytes.Value > 0)
                {
                    var raw = (double)readSoFar / totalBytes.Value * 100.0;
                    var pct = double.IsFinite(raw) ? Math.Max(0.0, Math.Min(100.0, raw)) : 0.0;
                    progress?.Report(new UpdateProgress { Stage = "Downloading Tor Expert Bundle...", PercentOfStage = pct });
                }
            }
            if (totalBytes.HasValue && totalBytes.Value > 0 && readSoFar != totalBytes.Value)
                throw new IOException($"Download truncated: got {readSoFar} of {totalBytes.Value} bytes. Current install untouched.");
        }

        static void RequireDiskSpace(string destPath, long? totalBytes)
        {
            try
            {
                // totalBytes is server-controlled: <= 0 means unknown (fall
                // back to the flat 500 MB floor), and a gigantic value must
                // never overflow the 2.5x estimate into a negative/wrapped
                // long that bypasses the check and fills the disk.
                long required;
                if (totalBytes.HasValue && totalBytes.Value > 0)
                {
                    long total = totalBytes.Value;
                    try
                    {
                        checked
                        {
                            // 2.5x = 2x + half, all in integers (no double→long
                            // cast, which yields long.MinValue on overflow and
                            // would pass the free-space check spuriously).
                            required = total * 2 + total / 2 + 50L * 1024 * 1024;
                        }
                    }
                    catch (OverflowException)
                    {
                        // Absurd Content-Length: demand the impossible so the
                        // download refuses instead of filling the disk.
                        required = long.MaxValue;
                    }
                    if (required < 0) required = long.MaxValue;
                }
                else
                {
                    required = 500L * 1024 * 1024;
                }
                var root = Path.GetPathRoot(Path.GetFullPath(destPath));
                if (string.IsNullOrEmpty(root)) return;
                var free = new DriveInfo(root).AvailableFreeSpace;
                if (free < required)
                    throw new IOException(
                        $"Not enough disk space on {root} (need ~{required / 1024 / 1024} MB free, have {free / 1024 / 1024} MB). " +
                        "Free space and retry — current install untouched.");
            }
            catch (IOException) { throw; }
            catch { }
        }

        async Task VerifyChecksumAsync(string url, string filePath, IProgress<UpdateProgress>? progress)
        {
            progress?.Report(new UpdateProgress { Stage = "Verifying checksum..." });
            var slash = url.LastIndexOf('/');
            var name = url.Substring(slash + 1);
            var sumsUrl = url.Substring(0, slash + 1) + "sha256sums-unsigned-build.txt";

            string sums;
            try
            {
                using var client = CreateClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                sums = await client.GetStringAsync(sumsUrl, cts.Token);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Could not fetch checksums ({sumsUrl}) — refusing to install an unverifiable Tor binary. ({ex.GetType().Name})");
            }

            string? want = null;
            foreach (var line in sums.Split('\n'))
            {
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                if (parts[parts.Length - 1].TrimStart('*').Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    want = parts[0].Trim();
                    break;
                }
            }
            if (string.IsNullOrEmpty(want) || want.Length != 64 || !want.All(Uri.IsHexDigit))
                throw new InvalidOperationException(
                    $"Checksum file has no valid entry for {name} — refusing to install.");

            string got;
            using (var fs = File.OpenRead(filePath))
            using (var sha = SHA256.Create())
            {
                var hash = await Task.Run(() => sha.ComputeHash(fs));
                got = Convert.ToHexString(hash).ToLowerInvariant();
            }
            if (!got.Equals(want.ToLowerInvariant(), StringComparison.Ordinal))
                throw new InvalidOperationException(
                    $"Checksum MISMATCH for {name} (download corrupt or tampered) — deleted, current install untouched.");
        }

        async Task VerifySignatureAsync(string url, string filePath, IProgress<UpdateProgress>? progress)
        {
            progress?.Report(new UpdateProgress { Stage = "Verifying PGP signature..." });
            var ascUrl = url + ".asc";
            byte[] asc;
            try
            {
                using var client = CreateClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                asc = await client.GetByteArrayAsync(ascUrl, cts.Token);
            }
            catch (Exception ex)
            {
                // Fail closed: no signature means no install.
                throw new InvalidOperationException(
                    $"Could not fetch PGP signature ({ascUrl}) — refusing to install an unverifiable Tor binary. ({ex.GetType().Name})");
            }
            byte[] data;
            try { data = await File.ReadAllBytesAsync(filePath); }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Could not re-read download for PGP verification: " + ex.Message, ex);
            }
            var keyPath = Path.Combine(_toolsDir, "Tor", TorReleaseSigner.KeyFileName);
            try
            {
                await Task.Run(() => TorReleaseSigner.VerifyDetached(data, asc, keyPath));
            }
            catch (InvalidOperationException) { throw; }
            catch (Exception ex)
            {
                throw new InvalidOperationException("PGP verification failed: " + ex.Message, ex);
            }
        }

        static async Task ExtractTarGzAsync(string tarGzPath, string destDir)
        {
            await using var fileStream = File.OpenRead(tarGzPath);
            await using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
            await TarFile.ExtractToDirectoryAsync(gzipStream, destDir, overwriteFiles: true);
        }

        static void CopyDirectory(string sourceDir, string destDir)
        {
            Directory.CreateDirectory(destDir);
            foreach (var file in Directory.GetFiles(sourceDir))
                File.Copy(file, Path.Combine(destDir, Path.GetFileName(file)), overwrite: true);
            foreach (var dir in Directory.GetDirectories(sourceDir))
                CopyDirectory(dir, Path.Combine(destDir, Path.GetFileName(dir)));
        }

        // Keeps PTor's transport layer intact across upstream bundle swaps.
        // Restores from the pre-update backup into the fresh tree:
        //   1. pt_config.json — always ours (upstream still ships the broken
        //      snowflake→lyrebird mapping; theirs would re-break Snowflake).
        //   2. Any helper binary upstream doesn't ship (e.g. a user-installed
        //      snowflake-client.exe) — without this every Tor update deletes it.
        // Upstream's own helpers (lyrebird, conjure-client, READMEs) are left
        // alone so they keep updating. No-op on fresh installs (no backup).
        // Never throws anything but IOException (caller rolls back).
        static void PreservePluggableTransports(string? backupDir, string destTorDir)
        {
            try
            {
                if (string.IsNullOrEmpty(backupDir) || !Directory.Exists(backupDir)) return;
                var backupPt = Path.Combine(backupDir, "pluggable_transports");
                if (!Directory.Exists(backupPt)) return;
                var destPt = Path.Combine(destTorDir, "pluggable_transports");
                Directory.CreateDirectory(destPt);
                var backupConfig = Path.Combine(backupPt, "pt_config.json");
                if (File.Exists(backupConfig))
                    File.Copy(backupConfig, Path.Combine(destPt, "pt_config.json"), overwrite: true);
                foreach (var file in Directory.GetFiles(backupPt))
                {
                    var name = Path.GetFileName(file);
                    if (name.Equals("pt_config.json", StringComparison.OrdinalIgnoreCase)) continue;
                    var dest = Path.Combine(destPt, name);
                    if (!File.Exists(dest))
                        File.Copy(file, dest);
                }
            }
            catch (IOException) { throw; }
            catch (Exception ex)
            {
                throw new IOException("Could not preserve pluggable transports: " + ex.Message, ex);
            }
        }

        void WriteSentinel(string url)
        {
            try { File.WriteAllText(SentinelPath(), $"incomplete|{DateTime.UtcNow:o}|{url}"); } catch { }
        }

        void ClearSentinel() => TryDelete(SentinelPath());
        string SentinelPath() => Path.Combine(_toolsDir, "install.incomplete");

        static InvalidOperationException RestoreBackup(string destTorDir, string? backupDir, string reason)
        {
            try
            {
                if (backupDir != null)
                {
                    TryDeleteDir(destTorDir);
                    Directory.Move(backupDir, destTorDir);
                    return new InvalidOperationException(reason + " Previous version restored from backup.");
                }
                return new InvalidOperationException(reason + " No backup existed to restore.");
            }
            catch (Exception ex)
            {
                return new InvalidOperationException(
                    reason + $" AND rollback failed ({ex.Message}) — previous version is in {backupDir}.", ex);
            }
        }

        void PruneBackups(string? keep)
        {
            if (keep == null) return; // fresh install, no history of ours to prune
            try
            {
                foreach (var dir in Directory.GetDirectories(_toolsDir, "Tor_backup_*"))
                {
                    if (!dir.Equals(keep, StringComparison.OrdinalIgnoreCase))
                        TryDeleteDir(dir);
                }
            }
            catch { }
        }

        public const string BundleVersionFileName = "TorBundle.version";

        string BundleVersionPath() => Path.Combine(_toolsDir, BundleVersionFileName);

        public string? GetInstalledBundleVersion()
        {
            try
            {
                var p = BundleVersionPath();
                if (!File.Exists(p)) return null;
                var v = File.ReadAllText(p).Trim();
                return string.IsNullOrEmpty(v) ? null : v;
            }
            catch { return null; }
        }

        public bool HasTorExecutable()
        {
            try
            {
                return File.Exists(Path.Combine(_toolsDir, "Tor", "tor.exe"))
                    || File.Exists(Path.Combine(_toolsDir, "tor.exe"));
            }
            catch { return false; }
        }

        internal static bool IsSameBundleVersion(string? installed, string? latest) =>
            !string.IsNullOrWhiteSpace(installed) && !string.IsNullOrWhiteSpace(latest)
            && !latest.Equals("unknown", StringComparison.OrdinalIgnoreCase)
            && installed.Trim().Equals(latest.Trim(), StringComparison.OrdinalIgnoreCase);

        void WriteInstalledBundleVersion(string version)
        {
            try { File.WriteAllText(BundleVersionPath(), version); } catch { }
        }

        public static void RecoverIncompleteInstall(string toolsDir, Action<string> log)
        {
            var sentinel = Path.Combine(toolsDir, "install.incomplete");
            if (!File.Exists(sentinel)) return;
            log?.Invoke("Previous Tor update did not finish — recovering...");
            try
            {
                var dest = Path.Combine(toolsDir, "Tor");
                var backups = Directory.GetDirectories(toolsDir, "Tor_backup_*");
                Array.Sort(backups, StringComparer.OrdinalIgnoreCase);
                Array.Reverse(backups);
                if (backups.Length == 0)
                {
                    TryDelete(sentinel);
                    throw new FileNotFoundException(
                        "A previous Tor update crashed with no backup to restore. Reinstall the Tor bundle manually.");
                }
                TryDeleteDir(dest);
                Directory.Move(backups[0], dest);
                TryDelete(sentinel);
                log?.Invoke("Recovered previous Tor version from backup. Re-run the update when ready.");
            }
            catch (FileNotFoundException) { throw; }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "Could not recover crashed Tor update: " + ex.Message + ". Reinstall manually.", ex);
            }
        }

        static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }

        static void TryDeleteDir(string path)
        {
            try { if (Directory.Exists(path)) Directory.Delete(path, recursive: true); } catch { }
        }
    }
}
