# PTor

Tor traffic router for Windows, plus an `Uninstall` companion.

Routes this Windows user's apps through Tor via the system proxy and inherited
env vars, with an optional Tor-only packet lockdown (WinDivert). Single
instance — only one copy runs at a time. Ad/tracker blocking is enforced
100% in-app (DNS + relays); the OS `hosts` file is never touched.

## Layout

- `src/` — all source: the `PTor` WPF app, the `Uninstall` console companion,
  the bundled `tools/` (Tor Expert Bundle, pluggable transports, GeoIP data,
  WinDivert driver), `rescue-internet.bat`, and the user-facing `README.md`.
- `Release/` folders, `bin/`, `obj/` are local build outputs and are not
  committed. Ship binaries through GitHub Releases instead.

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

## If your internet breaks

1. Start PTor again — it detects stale proxy/env/DNS state on boot and
   repairs it automatically.
2. If PTor won't start, run `rescue-internet.bat` (next to `PTor.exe`) as
   administrator — the same repair without the app.
3. Last resort: run `Uninstall.exe` as administrator, then reboot when it
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
