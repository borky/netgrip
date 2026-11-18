package modules

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func npReset(t *testing.T) {
	t.Helper()
	npNames.Store(nil)
	old := npNow
	t.Cleanup(func() { npNames.Store(nil); npNow = old })
}

func TestWithNetPulseNamesOnlyFillsBareAddresses(t *testing.T) {
	npReset(t)
	clients := []Client{
		{MAC: "02:00:00:00:00:01", Name: "02:00:00:00:00:01"},              // nothing named it
		{MAC: "02:00:00:00:00:02", Name: "laptop"},                         // its lease
		{MAC: "02:00:00:00:00:03", Name: "nas", NameSource: "reservation"}, // the reservation
		{MAC: "02:00:00:00:00:04", Name: "X1C", NameSource: "quarantine"},  // the quarantine
		{MAC: "02:00:00:00:00:05", Name: "My TV"},                          // a name set here
		{MAC: "02:00:00:00:00:06", Name: "02:00:00:00:00:06"},              // NetPulse has none
	}
	// No NetPulse at all: the same list.
	got := WithNetPulseNames(clients)
	for i := range got {
		if got[i].Name != clients[i].Name || got[i].NameSource != clients[i].NameSource {
			t.Fatalf("changed without NetPulse: %+v", got[i])
		}
	}
	NoteNetPulseNames(map[string]string{
		"02:00:00:00:00:01": "Living Room TV",
		"02:00:00:00:00:02": "Other name",
		"02:00:00:00:00:03": "Other name",
		"02:00:00:00:00:04": "Other name",
		"02:00:00:00:00:05": "Other name",
	})
	got = WithNetPulseNames(clients)
	if got[0].Name != "Living Room TV" || got[0].NameSource != "netpulse" {
		t.Fatalf("bare address not named: %+v", got[0])
	}
	for i := 1; i < len(clients); i++ {
		if got[i].Name != clients[i].Name || got[i].NameSource != clients[i].NameSource {
			t.Errorf("a client with a name of its own changed: %+v", got[i])
		}
	}
	if clients[0].Name != "02:00:00:00:00:01" {
		t.Fatal("the list passed in was changed")
	}
}

func TestNoteNetPulseNamesKeepsOnlyCleanData(t *testing.T) {
	npReset(t)
	NoteNetPulseNames(map[string]string{
		"02:00:00:00:00:01": "  Printer\t\tHall  ",
		"02:00:00:00:00:02": "evil‮exe.jpg",                  // a direction override
		"02:00:00:00:00:03": "line\nbreak\x00",               // control characters
		"02:00:00:00:00:04": "AA:BB:CC:DD:EE:FF",             // an address, not a name
		"02:00:00:00:00:05": strings.Repeat("x", 200),        // too long
		"02:00:00:00:00:06": "",                              // empty
		"not-a-mac":         "Ghost",                         // no usable MAC
		"02-00-00-00-00-07": "Dashes",                        // not the form NetGrip keys on
		"02:00:00:00:00:08": string([]byte{0xff, 0xfe, 'a'}), // not UTF-8
		"02:00:00:00:00:09": "Soft\u00adhyphen\u2060x",       // invisible format characters
		"02:00:00:00:00:0a": "می‌خواهم 👨‍👩",                  // ZWNJ and ZWJ stay
	})
	cases := map[string]string{
		"02:00:00:00:00:01": "Printer Hall",
		"02:00:00:00:00:02": "evilexe.jpg",
		"02:00:00:00:00:03": "line break",
		"02:00:00:00:00:04": "",
		"02:00:00:00:00:05": strings.Repeat("x", npNameMaxLen),
		"02:00:00:00:00:06": "",
		"02:00:00:00:00:07": "",
		"02:00:00:00:00:08": "",
		"02:00:00:00:00:09": "Softhyphenx",
		"02:00:00:00:00:0a": "می‌خواهم 👨‍👩",
	}
	for mac, want := range cases {
		if got := netpulseNameFor(mac); got != want {
			t.Errorf("%s: %q, want %q", mac, got, want)
		}
	}
	// Bounded.
	big := map[string]string{}
	for i := 0; i < npNamesMax+100; i++ {
		big[fmt.Sprintf("02:00:00:%02x:%02x:%02x", i>>16&0xff, i>>8&0xff, i&0xff)] = "n"
	}
	NoteNetPulseNames(big)
	if n := len(npNames.Load().names); n != npNamesMax {
		t.Fatalf("kept %d names", n)
	}
}

func TestNetPulseNamesExpireAndCanBeEmptied(t *testing.T) {
	npReset(t)
	now := time.Unix(1_700_000_000, 0)
	npNow = func() time.Time { return now }
	NoteNetPulseNames(map[string]string{"02:00:00:00:00:01": "Printer"})
	c := []Client{{MAC: "02:00:00:00:00:01", Name: "02:00:00:00:00:01"}}
	if WithNetPulseNames(c)[0].Name != "Printer" {
		t.Fatal("not named")
	}
	// NetPulse down for more than a day: back to the address.
	now = now.Add(25 * time.Hour)
	if WithNetPulseNames(c)[0].Name != "02:00:00:00:00:01" {
		t.Fatal("a day-old name still shown")
	}
	// A reply with no names (NetPulse knows none now): none shown.
	NoteNetPulseNames(map[string]string{})
	if WithNetPulseNames(c)[0].Name != "02:00:00:00:00:01" {
		t.Fatal("an empty reply kept old names")
	}
}
