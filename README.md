# PTor

Tor traffic router.  
PTor will re-route all traffics through TOR network automatically without touching proxy settings on individual app.

## Build

Requires the .NET 10 SDK.

```bat
cd src
build-release.bat         :: patch bump (1.2.0 -> 1.2.1)
build-release.bat minor   :: minor bump
build-release.bat 2.1.0   :: explicit version
```

This publishes self-contained single-file `PTor.exe` + `Uninstall.exe` (plus
`README.md` and `rescue-internet.bat`) into `src/Release/vX.Y.Z/`.
Debug builds run unelevated; Release builds require administrator rights
(needed for the lockdown driver and DNS repair).

## How-to recover when losing direct connection after use.

1. If PTor won't start, run `rescue-internet.bat` (next to `PTor.exe`) as
   administrator — the same repair without the app.
2. Last resort: run `Uninstall.exe` as administrator, then reboot when it
   finishes (it enforces this). Details in `src/README.md`.

## Licensing

- **PTor's own source code** (everything outside `src/tools/`, plus the
  `Uninstall` project): **MIT License** — see `LICENSE`.
- **WinDivert** (the packet-diversion driver used only by the optional
  Tor-only lockdown): its authors dual-license it under **LGPL-3.0 or
  GPL-2.0** (their choice of wording, their license — not ours). It is used
  unmodified as a dynamically loaded driver; the full license text ships with
  it at `src/tools/WinDivert/LICENSE.txt` (version note in `VERSION.txt`).
  Keep those files with any redistribution.
- **Bundled third-party components** — the Tor Expert Bundle (`tor.exe`,
  pluggable transports), GeoIP data, and docs under `src/tools/` belong to
  their respective projects; see the notices in `src/tools/docs/` and
  `src/tools/tor/`. The `BouncyCastle.Cryptography` NuGet dependency is MIT
  licensed.
