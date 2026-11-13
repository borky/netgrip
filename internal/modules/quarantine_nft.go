package modules

// Device quarantine: the firewall side.
//
// The quarantine plugs into firewall4 through UCI `include` sections, never
// through a table of its own:
//
//   - one `table-prepend` include holds the sets and the two chains
//     (netgrip_q_input, netgrip_q_forward), with the approved MACs written
//     into the set, so a firewall reload or a reboot recreates everything
//     already filled: there is no empty-set window in which approved devices
//     would be cut off;
//   - per protected zone, a `chain-prepend` include puts one jump at the top
//     of fw4's own input_<zone> and forward_<zone> chains. fw4 builds those
//     chains from the zone's own networks and devices, so no interface,
//     bridge or VLAN name is ever written here.
//
// Because the hook-up is plain UCI in /etc/config/firewall, turning the
// feature on is reverted by the panel's confirm window like any other risky
// firewall change, and removing the include sections removes everything.
//
// Runtime changes (an approval, a mode change, a pause) are applied to the
// live chains and sets with `nft -f` transactions and written to the include
// file first, so the next reload loads the same state.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	qTable        = "fw4" // firewall4's table: the include lives inside it
	qSetOK        = "netgrip_q_ok"
	qSetSeen      = "netgrip_q_seen"
	qSetWan       = "netgrip_q_wan"
	qSetPriv4     = "netgrip_q_private4"
	qSetPriv6     = "netgrip_q_private6"
	qSetDNS4      = "netgrip_q_dns4"
	qSetDNS6      = "netgrip_q_dns6"
	qSetOff       = "netgrip_q_off"
	qChainInput   = "netgrip_q_input"
	qChainForward = "netgrip_q_forward"

	// UCI section names of the includes. All start with qSectionPrefix so
	// the feature can find and remove every one of its sections.
	qSectionPrefix = "netgrip_q"
	qSectionTable  = "netgrip_q_table"
)

// quarantineDir holds the include files; a var so tests can redirect it.
var quarantineDir = "/etc/netgrip/quarantine"

func qTableFile() string   { return filepath.Join(quarantineDir, "table.nft") }
func qInputFile() string   { return filepath.Join(quarantineDir, "input.nft") }
func qForwardFile() string { return filepath.Join(quarantineDir, "forward.nft") }

// Address ranges that are never "the internet": private, shared (CGNAT),
// link-local, loopback, multicast and reserved space. In "internet" mode a
// quarantined device may not reach them even through a WAN interface, which
// covers an upstream modem's web UI and double-NAT neighbours.
var (
	qPrivate4 = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
	}
	qPrivate6 = []string{"::/127", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// qSeenTimeout is how long a quarantined MAC stays in the "seen" set after
// its last new connection; the poller derives "last seen" from it.
const qSeenTimeout = 3600

// qRuleSet is everything the generated chains depend on. A pause "off" is
// not part of it: it lives in the kernel as a timed element of
// netgrip_q_off, so it ends on time even without NetGrip, and a firewall
// reload (which starts the set empty) ends it on the safe side.
type qRuleSet struct {
	Mode     string   // "internet" | "nothing"
	Approved []string // lowercase MACs
	Wan      []string // WAN-side interface names (runtime-derived)
	DNS      []string // DNS servers handed out by DHCP (IPv4 or IPv6)
}

// reIfname: what nft accepts as an interface name in a set element, quoted.
var reIfname = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)

// sortedMACs returns the valid, unique, lowercase MACs in a stable order.
func sortedMACs(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, m := range in {
		m = strings.ToLower(strings.TrimSpace(m))
		if !reMac.MatchString(m) || seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func sortedIfnames(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, n := range in {
		if !reIfname.MatchString(n) || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func quoted(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

// elementsLine is ` elements = { a, b }` or "" for an empty set (nft refuses
// an empty element list).
func elementsLine(elems []string) string {
	if len(elems) == 0 {
		return ""
	}
	return " elements = { " + strings.Join(elems, ", ") + " };"
}

// qHeadRules start both chains. Traffic from an interface without an
// Ethernet header (WireGuard, OpenVPN tun, PPP, GRE...) carries no MAC to
// judge: it leaves untouched, or a VPN in a protected zone would be cut off.
// Approved MACs leave next; everything else is recorded in the seen set and
// then, during a pause "off", leaves too.
func qHeadRules() []string {
	return []string{
		"meta iiftype != ether return",
		"ether saddr @" + qSetOK + " return",
		"update @" + qSetSeen + " { ether saddr }",
		"meta nfproto @" + qSetOff + " return",
	}
}

// qDNSRules let DNS through when the router redirected it (a "force DNS"
// DNAT, to whatever port) or when it goes to a resolver DHCP hands out.
func qDNSRules() []string {
	return []string{
		"ct status dnat ct original proto-dst 53 return",
		"ip daddr @" + qSetDNS4 + " meta l4proto { tcp, udp } th dport 53 return",
		"ip6 daddr @" + qSetDNS6 + " meta l4proto { tcp, udp } th dport 53 return",
	}
}

// qInputRules are the rules of netgrip_q_input, one per line. A device that
// is not approved may still get an address and names from the router (DHCP,
// DHCPv6, DNS, NTP, IPv6 neighbour discovery); everything else addressed to
// the router - the panel, SSH, LuCI - is refused.
func qInputRules(rs qRuleSet) []string {
	r := append(qHeadRules(), qDNSRules()...)
	return append(r,
		"udp dport { 53, 67, 123, 547 } return",
		"tcp dport 53 return",
		"icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } return",
		`counter reject comment "netgrip quarantine"`,
	)
}

// qForwardRules are the rules of netgrip_q_forward. "internet": out through
// a WAN interface, to a public address, only. "nothing": no forwarding.
// With no WAN interface known the oifname test matches everything, so
// "internet" fails closed rather than open.
func qForwardRules(rs qRuleSet) []string {
	r := append(qHeadRules(), qDNSRules()...)
	if rs.Mode == "internet" {
		return append(r,
			`oifname != @`+qSetWan+` counter reject comment "netgrip quarantine"`,
			`ip daddr @`+qSetPriv4+` counter reject comment "netgrip quarantine"`,
			`ip6 daddr @`+qSetPriv6+` counter reject comment "netgrip quarantine"`,
			"return",
		)
	}
	return append(r, `counter reject comment "netgrip quarantine"`)
}

// renderQTable renders the table-prepend include: sets and chains, as fw4
// splices it into `table inet fw4 { ... }`.
func renderQTable(rs qRuleSet) string {
	var b strings.Builder
	b.WriteString("# Generated by NetGrip (device quarantine). Do not edit: rewritten on every change.\n")
	fmt.Fprintf(&b, "set %s { type ether_addr;%s }\n", qSetOK, elementsLine(sortedMACs(rs.Approved)))
	fmt.Fprintf(&b, "set %s { type ether_addr; size 16384; flags dynamic, timeout; timeout %ds; }\n", qSetSeen, qSeenTimeout)
	fmt.Fprintf(&b, "set %s { type nf_proto; flags timeout; }\n", qSetOff)
	fmt.Fprintf(&b, "set %s { type ifname;%s }\n", qSetWan, elementsLine(quoted(sortedIfnames(rs.Wan))))
	fmt.Fprintf(&b, "set %s { type ipv4_addr; flags interval;%s }\n", qSetPriv4, elementsLine(qPrivate4))
	fmt.Fprintf(&b, "set %s { type ipv6_addr; flags interval;%s }\n", qSetPriv6, elementsLine(qPrivate6))
	dns4, dns6 := splitIPs(rs.DNS)
	fmt.Fprintf(&b, "set %s { type ipv4_addr;%s }\n", qSetDNS4, elementsLine(dns4))
	fmt.Fprintf(&b, "set %s { type ipv6_addr;%s }\n", qSetDNS6, elementsLine(dns6))
	writeChain(&b, qChainInput, qInputRules(rs), "")
	writeChain(&b, qChainForward, qForwardRules(rs), "")
	return b.String()
}

func writeChain(b *strings.Builder, name string, rules []string, indent string) {
	fmt.Fprintf(b, "%schain %s {\n", indent, name)
	for _, r := range rules {
		fmt.Fprintf(b, "%s\t%s\n", indent, r)
	}
	fmt.Fprintf(b, "%s}\n", indent)
}

// The chain-prepend includes: one line each, the same for every zone.
func renderQInputJump() string   { return "jump " + qChainInput + "\n" }
func renderQForwardJump() string { return "jump " + qChainForward + "\n" }

// renderQRuntimeUpdate is one nft transaction that brings the live chains,
// the approved set and the WAN set in line with rs, without a firewall
// reload: flushes and refills, applied atomically by `nft -f`.
func renderQRuntimeUpdate(rs qRuleSet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s %s\n", qTable, qChainInput)
	fmt.Fprintf(&b, "flush chain inet %s %s\n", qTable, qChainForward)
	fmt.Fprintf(&b, "flush set inet %s %s\n", qTable, qSetOK)
	fmt.Fprintf(&b, "flush set inet %s %s\n", qTable, qSetWan)
	fmt.Fprintf(&b, "flush set inet %s %s\n", qTable, qSetDNS4)
	fmt.Fprintf(&b, "flush set inet %s %s\n", qTable, qSetDNS6)
	if m := sortedMACs(rs.Approved); len(m) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", qTable, qSetOK, strings.Join(m, ", "))
	}
	if w := sortedIfnames(rs.Wan); len(w) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", qTable, qSetWan, strings.Join(quoted(w), ", "))
	}
	dns4, dns6 := splitIPs(rs.DNS)
	if len(dns4) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", qTable, qSetDNS4, strings.Join(dns4, ", "))
	}
	if len(dns6) > 0 {
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", qTable, qSetDNS6, strings.Join(dns6, ", "))
	}
	fmt.Fprintf(&b, "table inet %s {\n", qTable)
	writeChain(&b, qChainInput, qInputRules(rs), "\t")
	writeChain(&b, qChainForward, qForwardRules(rs), "\t")
	b.WriteString("}\n")
	return b.String()
}

// renderQCheck wraps the include content in a throwaway table so `nft -c`
// can validate it against the running kernel (set flags, dynset, reject)
// before the real firewall ever loads it.
func renderQCheck(rs qRuleSet) string {
	var b strings.Builder
	b.WriteString("table inet netgrip_q_check {\n")
	b.WriteString(renderQTable(rs))
	b.WriteString("chain zone_input {\n\t" + strings.TrimSpace(renderQInputJump()) + "\n}\n")
	b.WriteString("chain zone_forward {\n\t" + strings.TrimSpace(renderQForwardJump()) + "\n}\n")
	b.WriteString("}\n")
	return b.String()
}

// nftRunFn runs nft with args and optional stdin; a var so tests never run
// the real binary.
var nftRunFn = func(stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command("nft", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

func nftApply(script string) error {
	if out, err := nftRunFn(script, "-f", "-"); err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// nftCheck validates a script without applying it.
func nftCheck(script string) error {
	if out, err := nftRunFn(script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft check: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// writeQFiles writes the three include files, durably: a jump file whose
// table file is missing or truncated would make firewall4 reject its whole
// ruleset at the next boot. The rules are validated by the kernel first,
// and the table file goes first: the jumps need its chains.
func writeQFiles(rs qRuleSet) error {
	if err := nftCheck(renderQCheck(rs)); err != nil {
		return err
	}
	if err := os.MkdirAll(quarantineDir, 0o755); err != nil {
		return err
	}
	if err := writeFileDurable(qTableFile(), []byte(renderQTable(rs))); err != nil {
		return err
	}
	if err := writeFileDurable(qInputFile(), []byte(renderQInputJump())); err != nil {
		return err
	}
	return writeFileDurable(qForwardFile(), []byte(renderQForwardJump()))
}

// writeFileDurable writes via a temp file, fsyncs it, renames it into place
// and fsyncs the directory, so a power cut leaves the old or the new file,
// never an empty one.
func writeFileDurable(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// removeQFiles deletes the include files, jumps first (a jump without its
// chains would break the firewall; chains without jumps are harmless).
func removeQFiles() {
	for _, f := range []string{qInputFile(), qForwardFile(), qTableFile()} {
		_ = os.Remove(f)
	}
}

// splitIPs separates valid IPv4 and IPv6 addresses.
func splitIPs(in []string) (v4, v6 []string) {
	seen := map[string]bool{}
	for _, s := range in {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		if ip.To4() != nil {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// qOffPauseScript sets or clears the kernel-timed pause "off".
func qOffPauseScript(remaining int64) string {
	s := fmt.Sprintf("flush set inet %s %s\n", qTable, qSetOff)
	if remaining > 0 {
		s += fmt.Sprintf("add element inet %s %s { ipv4 timeout %ds, ipv6 timeout %ds }\n", qTable, qSetOff, remaining, remaining)
	}
	return s
}

// qLiveChainsPresent reports whether fw4 has loaded the quarantine chains:
// the actual state, not the configured one.
func qLiveChainsPresent() bool {
	_, err1 := nftRunFn("", "list", "chain", "inet", qTable, qChainInput)
	_, err2 := nftRunFn("", "list", "chain", "inet", qTable, qChainForward)
	return err1 == nil && err2 == nil
}

// qSetElements reads the elements of a live set (MACs or names), whatever
// shape nft's JSON gives them (plain values, or objects with timeouts).
func qSetElements(set string) ([]string, error) {
	el, err := qSetElementsTimed(set)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(el))
	for i, e := range el {
		out[i] = e.Val
	}
	return out, nil
}

// qElem is a set element and, for timed sets, the seconds left.
type qElem struct {
	Val     string
	Expires int64
}

func qSetElementsTimed(set string) ([]qElem, error) {
	raw, err := nftRunFn("", "-j", "list", "set", "inet", qTable, set)
	if err != nil {
		return nil, fmt.Errorf("nft list set %s: %w", set, err)
	}
	return parseNftSetElementsTimed(raw)
}

func parseNftSetElements(raw []byte) ([]string, error) {
	el, err := parseNftSetElementsTimed(raw)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(el))
	for i, e := range el {
		out[i] = e.Val
	}
	return out, nil
}

func parseNftSetElementsTimed(raw []byte) ([]qElem, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := []qElem{}
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			var s string
			if json.Unmarshal(e, &s) == nil {
				out = append(out, qElem{Val: strings.ToLower(s)})
				continue
			}
			var obj struct {
				Elem struct {
					Val     json.RawMessage `json:"val"`
					Expires int64           `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(e, &obj) == nil && json.Unmarshal(obj.Elem.Val, &s) == nil {
				out = append(out, qElem{Val: strings.ToLower(s), Expires: obj.Elem.Expires})
			}
		}
	}
	return out, nil
}
