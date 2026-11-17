# Router buttons

Actions a physical button on the router runs, to get back into a router
when something breaks. Settings → Router buttons.

## Actions

| Action | What it does |
| --- | --- |
| Switch a Wi-Fi network on/off | Flips one access point (`wireless.<section>.disabled`). Optionally switches it back after a time; a press during that time, or a reboot, switches it back at once. NetGrip's Wi-Fi schedule leaves the network alone meanwhile. |
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
package; without a required one the feature stays off.

| Needs | Package | Without it |
| --- | --- | --- |
| procd's button rule (`/etc/hotplug.json` → `/etc/rc.button`) | `procd`, `base-files` | Required |
| `gpio-button-hotplug` | `kmod-gpio-button-hotplug` | Required: buttons send no events |
| `awk` | `busybox` (awk) or `gawk` | Required |
| `uci` | `uci` | Required |
| `wifi` | `wifi-scripts` (`base-files` before 24.10) | No Wi-Fi action |
| `flock` or `lock` | `busybox` | Two actions at the very same moment may interleave |
| `setsid` | `busybox` | Actions stay attached to procd's button handler; they still run |
| `md5sum` or `sha256sum` | `busybox` | A Wi-Fi config saved at the same moment is noticed by size only |

Tested on OpenWrt 25.12 (busybox 1.37, apk) with busybox's own `awk`,
`sed` and `grep`, and with a PATH holding only basic busybox applets (no
`flock`, `lock`, `setsid`, `md5sum`).
