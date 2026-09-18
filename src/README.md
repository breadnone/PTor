# PTor — Tor Traffic Router

Routes this Windows user's apps through Tor (system proxy + inherited env vars,
optional Tor-only packet lockdown). Single instance: only one copy runs at a time.

## If your internet stops working

PTor keeps your original proxy / env / DNS settings backed up and restores them
on stop. After a hard crash or a Task Manager kill, leftovers can keep you
offline. Fix it in this order:

1. **Start PTor again.** It detects stale state on boot and repairs it
   automatically (proxy, env vars, DNS, driver leftovers).
2. **If PTor won't start, run `rescue-internet.bat` as administrator.**
   It lives next to `PTor.exe`. It restores your proxy, environment variables
   and DNS resolvers, flushes the DNS cache, clears stale checkpoints and
   removes a leftover WinDivert driver service — but only entries PTor marked
   as its own. Anything else is left untouched. Safe to run anytime.
3. **Last resort: run `Uninstall.exe` as administrator.** It stops PTor,
   restores everything in step 2, deletes PTor's registry keys
   (`HKCU\Software\PTor`, `HKLM\SOFTWARE\PTor`), removes PTor's own WinDivert
   driver service (a foreign one is left alone and reported), deletes
   `%AppData%\PTor` and `%ProgramData%\PTor`, and can delete the program
   folder itself.
   - Flags: `--dry-run` (show what would happen, change nothing),
     `--yes` (no prompts), `--no-reboot` (skip the reboot step),
     `--log <file>` (write a log).
   - **Reboot when it is done — Uninstall.exe enforces this** (schedules a
     restart with a 60-second countdown, abortable with `shutdown /a`).
     The reboot clears any in-use driver/network state so you come back
     online cleanly.

## Notes

- PTor never touches the OS `hosts` file. There is no filter-list adblocking;
  only your own manual Blocked Domains list (Config) is enforced, plus
  internal-only names that must never leave the machine.
- PTor installs exactly one WinDivert driver service, only while Tor-only
  lockdown is on, and removes it on stop. It never touches another app's
  driver.
