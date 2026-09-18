package modules

import "testing"

// The shape nlbw prints: a column list plus positional rows. Columns are
// looked up by name because the order differs per grouping, so these
// fixtures deliberately use two different orders.
const nlbwDevicesJSON = `{"columns":["mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],
 "data":[["02:00:00:00:00:01","192.0.2.11",99,5000,10,1000,9],
         ["02:00:00:00:00:02","192.0.2.12",5,300,4,100,3],
         ["02:00:00:00:00:01","192.0.2.99",1,1,1,1,1],
         ["00:00:00:00:00:00","",7,999999,9,999999,9]]}`

const nlbwAppsJSON = `{"columns":["proto","port","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts","layer7"],
 "data":[["TCP",443,10,900,3,100,2,"HTTPS"],
         ["UDP",443,4,40,1,10,1,"QUIC"],
         ["IP",0,2,7,1,3,1,null]]}`

func rowsFrom(t *testing.T, doc string) []map[string]any {
	t.Helper()
	rows, err := nlbwParse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rows
}

func TestNlbwDevicesAggregateByMAC(t *testing.T) {
	got := nlbwTop(nlbwAggregate(rowsFrom(t, nlbwDevicesJSON), deviceKey), 0)

	// Two devices: the repeated MAC is one device with its rows summed, and
	// the null MAC is not a device at all.
	if len(got) != 2 {
		t.Fatalf("devices: %+v", got)
	}
	if got[0].Key != "02:00:00:00:00:01" || got[0].DownBytes != 5001 || got[0].UpBytes != 1001 {
		t.Fatalf("first device: %+v", got[0])
	}
	if got[0].Conns != 100 {
		t.Fatalf("conns should add up: %+v", got[0])
	}
	// The IP is the first non-empty one for that MAC, not simply the
	// first: nlbw emits several rows per device and some carry none.
	if got[0].IP != "192.0.2.11" {
		t.Fatalf("ip: %+v", got[0])
	}
	// Sorted by total traffic, biggest first.
	if got[1].Key != "02:00:00:00:00:02" {
		t.Fatalf("order: %+v", got)
	}
}

func TestNlbwAppsNameTheUnnamed(t *testing.T) {
	got := nlbwTop(nlbwAggregate(rowsFrom(t, nlbwAppsJSON), appKey), 0)
	if len(got) != 3 {
		t.Fatalf("apps: %+v", got)
	}
	if got[0].Key != "HTTPS" || got[0].DownBytes != 900 {
		t.Fatalf("first app: %+v", got[0])
	}
	// A row nlbwmon cannot name is "other", never a bare port number.
	last := got[len(got)-1]
	if last.Key != "other" {
		t.Fatalf("unnamed row: %+v", last)
	}
}

func TestNlbwTopLimits(t *testing.T) {
	rows := nlbwTop(nlbwAggregate(rowsFrom(t, nlbwDevicesJSON), deviceKey), 1)
	if len(rows) != 1 || rows[0].Key != "02:00:00:00:00:01" {
		t.Fatalf("limit: %+v", rows)
	}
	// Never nil: the API returns [] rather than null.
	if empty := nlbwTop(nil, 5); empty == nil || len(empty) != 0 {
		t.Fatalf("empty: %+v", empty)
	}
}

func TestNlbwParseRejectsGarbage(t *testing.T) {
	if _, err := nlbwParse([]byte("nlbw: no database")); err == nil {
		t.Fatal("expected an error")
	}
}

// A device whose first row carries no address still gets one from a later
// row, so the card can label it by IP instead of falling back to the MAC.
func TestNlbwDeviceTakesFirstNonEmptyIP(t *testing.T) {
	const doc = `{"columns":["mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],
	 "data":[["02:00:00:00:00:07","",3,10,1,5,1],
	         ["02:00:00:00:00:07","192.0.2.77",4,20,1,5,1]]}`
	got := nlbwTop(nlbwAggregate(rowsFrom(t, doc), deviceKey), 0)
	if len(got) != 1 || got[0].IP != "192.0.2.77" {
		t.Fatalf("ip: %+v", got)
	}
	if got[0].DownBytes != 30 {
		t.Fatalf("bytes should still add up: %+v", got[0])
	}
}
