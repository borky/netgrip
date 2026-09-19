package modules

import "testing"

// A rule about traffic from the Internet has to name exactly one zone, and it
// must be a zone the uplink is actually in: UCI accepts a rule against any
// zone, fw4 reloads it without complaint, and it then matches nothing. A
// forward that silently forwards nothing is worse than one that fails loudly.
func TestPickInternetZone(t *testing.T) {
	cases := []struct {
		name  string
		zones map[string]bool
		want  string
	}{
		{
			// The conventional case, unchanged: one zone called wan.
			name:  "single conventional zone",
			zones: map[string]bool{"wan": true},
			want:  "wan",
		},
		{
			// The case this exists for: the uplink is in a zone named after
			// the provider, and nothing on the router is called "wan".
			name:  "zone named after the provider",
			zones: map[string]bool{"isp": true},
			want:  "isp",
		},
		{
			// Several outward zones (a wired line and a modem, say): any one
			// is defensible, but it must be the SAME one every time, or
			// repeated writes scatter rules across zones.
			name:  "stable choice among several",
			zones: map[string]bool{"isp": true, "cell": true, "backup": true},
			want:  "backup",
		},
		{
			// Nothing resolved: keep writing what was written before rather
			// than inventing a name no zone has.
			name:  "nothing resolves",
			zones: map[string]bool{},
			want:  "wan",
		},
		{
			name:  "false entries are not zones",
			zones: map[string]bool{"isp": false},
			want:  "wan",
		},
		{
			name:  "an empty name is not a zone",
			zones: map[string]bool{"": true},
			want:  "wan",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickInternetZone(c.zones); got != c.want {
				t.Errorf("pickInternetZone(%v) = %q, want %q", c.zones, got, c.want)
			}
		})
	}
}

// The choice must not depend on map iteration order, which Go randomises:
// otherwise two forwards created a minute apart can land in different zones.
func TestPickInternetZoneIsStable(t *testing.T) {
	zones := map[string]bool{"isp": true, "cell": true, "wan6": true}
	first := pickInternetZone(zones)
	for i := 0; i < 50; i++ {
		if got := pickInternetZone(zones); got != first {
			t.Fatalf("choice changed between calls: %q then %q", first, got)
		}
	}
}
