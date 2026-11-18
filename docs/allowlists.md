# Allow lists

Who may reach a port open to the Internet. Internet → "Who may reach your
open ports", and the "Allowed from" chip next to each open port (and under
remote HTTPS and SSH in Settings → Access from the Internet).

A list holds:

| Entry | Example | Meaning |
| --- | --- | --- |
| An address | `198.51.100.7`, `2001:db8::7` | That address. |
| A range | `198.51.100.0/24` | Every address in it. Ranges wider than /8 (IPv4) or /16 (IPv6) are refused. |
| A host name | `home.example.net` | Whatever the name resolves to (A and AAAA, up to 16 addresses), looked up every two minutes: a dynamic DNS name keeps following a home connection whose address changes. |

A port limited to a list can be reached from the Internet only by the
addresses on it. Lists do not apply to anything coming from the router's
own networks (NAT reflection included).

## Failing closed

- An empty list lets nobody in.
- A name that no longer exists (NXDOMAIN), or that points only at an
  address a list cannot hold (a dynamic DNS name parked at 0.0.0.0, a
  sinkhole at 127.0.0.1), is dropped at once: its old address may belong
  to someone else by then. Each family (A, AAAA) is looked up on its own,
  so a timeout in one does not drop the other.
- A name that cannot be looked up (DNS down, timeout) keeps its last
  address for the time the list allows (none, 1, 6 or 24 hours), then is
  dropped.
- A rule that refers to a set that is missing or disabled is dropped by
  fw4 entirely: it never falls back to "anyone".
- After a reboot the sets are empty until NetGrip fills them, seconds after
  it starts. If NetGrip is removed, the ports stay limited to sets nobody
  fills any more: they let nobody in until "Allowed from" is changed in
  LuCI (remove the rule's `ipset` option).

## How it is built

- Each list is two fw4 sets, `netgrip_allow_<id>_v4` and `_v6`
  (`match src_net`, `comment 'netgrip allowlists: list <id> (IPv4)'`),
  created the first time the list is used.
- A rule or port forward is limited with fw4's own `option ipset`. fw4
  limits a rule that uses a set to that set's family, so a port on the
  router that answers both IPv4 and IPv6 gets a twin rule for IPv6:
  `<section>_ngal6`, named `<name> (IPv6, netgrip allowlists)`. The twin
  copies the rule's options and is rewritten or removed when the rule
  changes (checked every two minutes and with each of NetGrip's own
  changes). An anonymous rule (LuCI makes them) is given a name first
  (`ngal_<hex>`), because an index like `@rule[27]` moves when other rules
  come and go. A port forward is IPv4 only and has no twin.
- The lists live in `/etc/netgrip/allowlists.json`, written only when they
  are edited. What a set holds (fixed entries plus what the names resolve
  to) is written to `/var/run/netgrip-allowlists/<set>.txt` (tmpfs), which
  fw4 loads on every reload (`option loadfile`); when it changes it is put
  into the running set in one nft transaction (flush and add together, so
  no packet ever sees it half done). Nothing is written to flash when an
  address changes.
- Changing a list's entries does not touch the firewall configuration;
  choosing who may reach a port does (one reload). Every firewall change
  is snapshotted, checked against the running firewall (the set exists and
  a rule uses it) and put back if anything is off.

## Cost

With no list, nothing runs. With lists: every two minutes the names are
looked up through the router's resolver by NetGrip itself (no command is
started), and the firewall configuration is read once (`uci show`). `nft`
runs only when a set's content changed, plus once every ten minutes to
refill a set something else emptied.

## Safety while connected from outside

When the panel is used from outside the router's own networks (through
an SSH tunnel, from the loopback address, or through a host a port forward
points at, such as a reverse proxy at home, counts as outside):

- limiting a port to a list that does not include the address the panel is
  used from asks first;
- removing that address from a list in use asks first;
- limiting a port arms the revert timer: unless "Keep" is pressed, the
  firewall is put back by itself (limiting remote HTTPS or SSH arms it
  from anywhere; from home otherwise it is not armed, as a missed "Keep"
  would open the port to everyone again);
- taking a set over is refused (the scheduled job it turns off is not part
  of a firewall rollback).

Removing a limit ("Anyone on the Internet") always asks first, from
anywhere.

## Taking over a set managed elsewhere

A set in the firewall config that is not one of NetGrip's lists (one a
script fills from cron, for example) is listed under "Managed outside
NetGrip". "Take over" proposes a list made of the host names found in the
script that fills it (kept only when they resolve to an address the set
holds now) and the set's other addresses, then in one firewall change:
creates the list, moves every port that used the set to it, and removes
the set. Each port keeps the family the old set gave it (a port that
answers both families but was limited to an IPv4 set gets `family ipv4`,
so IPv6 does not open on the way). Addresses the set allows now and the new list would not are
shown and must be confirmed. The scheduled job that filled the set is then
commented out in its crontab (kept, not deleted) and cron restarted.

A set cannot be taken over when a rule uses it to block (`!set`), when a
rule that is not a port open to the Internet uses it, or when it holds
something other than addresses.

## Requirements

fw4 (nftables) able to load a set from a file (`loadfile`). No package
to install. Older firewalls (fw3, iptables), or an fw4 without set files,
show the card as not available. Firewall changes staged elsewhere and not
applied (LuCI, a script) must be applied or discarded first: they are
never committed along with NetGrip's.
