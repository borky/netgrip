# Router buttons

Actions a physical button on the router runs, to get back into a router
when something breaks. Settings → Router buttons.

## Actions

| Action | What it does |
| --- | --- |
| Switch a Wi-Fi network on/off | Flips one access point (`wireless.<section>.disabled`). Optionally switches it back after a time; a press during that time, or a reboot, switches it back at once. NetGrip's Wi-Fi schedule leaves the network alone meanwhile. |
| Switch a Wi-Fi network on, off after a while | Turns one access point on whatever its state, and off again after the time chosen (or leaves it on). A press while it is on starts the time again; a reboot switches it off. |
| Pause or resume the device quarantine | Pauses NetGrip's quarantine (nothing enforced) for 1 minute to 24 hours, or resumes it when a pause runs; it resumes on its own when the time ends. The only action that needs NetGrip running: the script leaves a request file in `/tmp/netgrip-buttons` that NetGrip picks up at once. A press while NetGrip is down is logged as failed and never carried out later. |
| Restart the firewall | `/etc/init.d/firewall restart`. |
| Restart access | Restarts `dropbear`, `uhttpd`, `nginx` and `netgrip`, only those installed and enabled. |

Each can be assigned to a press, a double or triple press, or a hold of 2 to
30 seconds. A hold runs its action only if the button is let go within 2 s
of that time. A single press on a button that also has a double or triple
press acts about 1 s after it is let go (busybox `sleep` takes whole
seconds). An extra press right after an action is ignored.

## What does not change

- Presses nobody assigned do what the button always did: the wrapper hands
  them to the original script.
- Holding a button whose original script resets the router to factory
  settings (`factoryreset`, `jffs2reset` or `firstboot` after
  `"$SEEN" -ge N`) for N seconds or more always reaches it. A `reset`
  button whose script NetGrip cannot read gets no holds at all.
- Failsafe mode at boot (preinit) does not use these scripts.
- Switches (sliders, `TYPE=switch`) cannot take actions.

## How it works

For a button with actions, NetGrip keeps `/etc/rc.button/<button>` in
`/etc/netgrip/buttons/orig/` and puts a wrapper in its place that calls
`/usr/libexec/netgrip-button`, a shell script. The script needs nothing from
NetGrip when a button is pressed, and nothing runs between presses. A Wi-Fi
change is made on a private copy of `/etc/config/wireless`, so changes
someone else left unsaved in `/tmp/.uci` are never saved with it (`uci -t`
alone does not prevent that: uci applies `/tmp/.uci` deltas to every
command).

Files the feature writes, each marked `netgrip-managed-button`:
`/etc/rc.button/<button>` (wrappers), `/usr/libexec/netgrip-button`,
`/etc/hotplug.d/button/00-netgrip` (tells the panel which button was
pressed), `/etc/init.d/netgrip-buttons` (boot: switches back a timed
Wi-Fi change), `/etc/netgrip/buttons/`, `/tmp/netgrip-buttons/`.

The actions are stored in UCI (`netgrip.buttons`). An upgrade that replaces
a button script is repaired when NetGrip starts or the panel opens the card.
Removing every action of a button puts its original back; removing the
`netgrip` package puts every original back.

## Requirements

NetGrip installs none of these. The card lists what is missing, with the
package. Without a required one no action can be added; actions already
assigned are still listed and can be removed, and NetGrip keeps repairing
or removing its wrappers.

| Needs | Package | Without it |
| --- | --- | --- |
| procd's button rule (`/etc/hotplug.json` → `/etc/rc.button`) | `procd`, `base-files` | Required |
| `gpio-button-hotplug` or `button-hotplug` | `kmod-gpio-button-hotplug` (GPIO buttons) or `kmod-button-hotplug` (input-layer buttons, e.g. x86) | Required: buttons send no events |
| `awk` | `busybox` (awk) or `gawk` | Required |
| `uci` | `uci` | Required |
| `wifi` | `wifi-scripts` (`netifd` before 24.10) | No Wi-Fi action |
| `flock` or `lock` | `busybox` | Two actions at the very same moment may interleave |
| `setsid` | `busybox` | Actions stay attached to procd's button handler; they still run |
| `md5sum` or `sha256sum` | `busybox` | A Wi-Fi config saved at the same moment is noticed by its size and minute only |

`internal/modules/buttons/testdata/router-sandbox.sh` runs the script on a
router against a throwaway config in `/tmp`. Tested on OpenWrt 25.12 (busybox 1.37, apk) with busybox's own `awk`,
`sed` and `grep`, and with a PATH holding only basic busybox applets (no
`flock`, `lock`, `setsid`, `md5sum`).
