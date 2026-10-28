package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	mxTestRoom  = "!dummyRoomId"
	mxTestToken = "syt_dummy_token"
	mxTestUser  = "@netgrip-bot:example.org"
)

// useMatrixTempPaths points the config and the key at a fresh temp dir.
func useMatrixTempPaths(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oc, ok := matrixConfigPath, secretKeyPath
	matrixConfigPath = filepath.Join(dir, "matrix.json")
	secretKeyPath = filepath.Join(dir, "secrets.key")
	t.Cleanup(func() { matrixConfigPath, secretKeyPath = oc, ok })
	return dir
}

func TestMatrixConfigIsStoredSealed(t *testing.T) {
	dir := useMatrixTempPaths(t)
	if _, err := os.Stat(secretKeyPath); err == nil {
		t.Fatal("key exists before anything was saved")
	}
	in := MatrixConfig{Server: "https://matrix.example.org/", RoomID: mxTestRoom, Token: mxTestToken, Enabled: true}
	if err := SaveMatrixConfig(in); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(matrixConfigPath)
	for _, secret := range []string{"matrix.example.org", "dummyRoomId", mxTestToken} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("matrix.json holds %q in the clear: %s", secret, raw)
		}
	}
	for _, p := range []string{matrixConfigPath, secretKeyPath} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, err %v; want 0600", p, fi.Mode().Perm(), err)
		}
	}
	got := LoadMatrixConfig()
	if got.Server != "https://matrix.example.org" || got.RoomID != mxTestRoom || got.Token != mxTestToken || !got.Enabled || got.Unreadable {
		t.Fatalf("round trip = %+v", got)
	}
	// A different key leaves everything unreadable, never half-filled.
	if err := os.Remove(secretKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := secretKey(true); err != nil {
		t.Fatal(err)
	}
	got = LoadMatrixConfig()
	if !got.Unreadable || got.Server != "" || got.RoomID != "" || got.Token != "" {
		t.Fatalf("foreign key: %+v", got)
	}
	_ = dir
}

func TestSealedValueDoesNotOpenUnderAnotherField(t *testing.T) {
	useMatrixTempPaths(t)
	v, err := sealSecret(matrixFieldRoomID, mxTestRoom)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsealSecret(matrixFieldToken, v); err == nil {
		t.Fatal("a value sealed for one field opened under another")
	}
	if _, err := unsealSecret(matrixFieldToken, "plain"); err == nil {
		t.Fatal("a plaintext value was accepted")
	}
	again, _ := sealSecret(matrixFieldRoomID, mxTestRoom)
	if again == v {
		t.Fatal("two seals of the same value are identical: the nonce is not fresh")
	}
}

func TestSecretKeyEdgeCases(t *testing.T) {
	dir := useMatrixTempPaths(t)
	if err := os.Symlink(filepath.Join(dir, "gone"), secretKeyPath); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := sealSecret("k", "v"); err == nil {
		t.Fatal("a dangling symlink was accepted as a key")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	os.Remove(secretKeyPath)
	if err := os.WriteFile(secretKeyPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Reading with a truncated key fails; a save replaces it with a good one.
	if _, err := unsealSecret("k", sealedPrefix+"AAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("a truncated key opened a value")
	}
	v, err := sealSecret("k", "v")
	if err != nil {
		t.Fatalf("a save could not replace a truncated key: %v", err)
	}
	if key, _ := os.ReadFile(secretKeyPath); len(key) != secretKeyLen {
		t.Fatalf("replacement key is %d bytes", len(key))
	}
	if got, err := unsealSecret("k", v); err != nil || got != "v" {
		t.Fatalf("value sealed with the replacement key: %q, %v", got, err)
	}
}

func TestDamagedMatrixConfigIsUnreadableNotEmpty(t *testing.T) {
	useMatrixTempPaths(t)
	if err := os.WriteFile(matrixConfigPath, []byte(`{"server":"enc:v1:`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadMatrixConfig(); !got.Unreadable || got.Configured() {
		t.Fatalf("damaged file: %+v", got)
	}
	// Saving it switched off clears it.
	cfg, validate, err := MergeMatrixUpdate(LoadMatrixConfig(), MatrixUpdate{})
	if err != nil || validate {
		t.Fatalf("clear an unreadable config: %v %v", validate, err)
	}
	if err := SaveMatrixConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if got := LoadMatrixConfig(); got.Unreadable || got.Enabled {
		t.Fatalf("after clearing: %+v", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(matrixConfigPath))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestConcurrentFirstSealAgreesOnOneKey(t *testing.T) {
	useMatrixTempPaths(t)
	var wg sync.WaitGroup
	sealed := make([]string, 8)
	for i := range sealed {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sealed[i], _ = sealSecret("k", "v")
		}(i)
	}
	wg.Wait()
	for i, s := range sealed {
		if got, err := unsealSecret("k", s); err != nil || got != "v" {
			t.Fatalf("seal %d was made with a different key: %v", i, err)
		}
	}
}

func TestNormalizeMatrixConfig(t *testing.T) {
	ok := MatrixConfig{Server: "https://matrix.example.org", RoomID: mxTestRoom, Token: mxTestToken}
	if _, err := NormalizeMatrixConfig(ok); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if _, err := NormalizeMatrixConfig(MatrixConfig{}); err != nil {
		t.Fatalf("an empty config must be valid: %v", err)
	}
	for name, c := range map[string]MatrixConfig{
		"missing token": {Server: ok.Server, RoomID: ok.RoomID},
		"no scheme":     {Server: "matrix.example.org", RoomID: ok.RoomID, Token: ok.Token},
		"credentials":   {Server: "https://user:pass@example.org", RoomID: ok.RoomID, Token: ok.Token},
		"alias":         {Server: ok.Server, RoomID: "#room:example.org", Token: ok.Token},
		"public http":   {Server: "http://matrix.example.org", RoomID: ok.RoomID, Token: ok.Token},
	} {
		if _, err := NormalizeMatrixConfig(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, s := range []string{"http://localhost:8008", "http://127.0.0.1:8008", "http://10.0.0.5:8008"} {
		if _, err := NormalizeMatrixConfig(MatrixConfig{Server: s, RoomID: ok.RoomID, Token: ok.Token}); err != nil {
			t.Errorf("%s refused: %v", s, err)
		}
	}
}

func TestMergeMatrixUpdate(t *testing.T) {
	stored := MatrixConfig{Server: "https://matrix.example.org", RoomID: mxTestRoom, Token: mxTestToken, Enabled: true}

	// Blank fields keep the stored values.
	cfg, validate, err := MergeMatrixUpdate(stored, MatrixUpdate{Enabled: true})
	if err != nil || cfg.Token != mxTestToken || cfg.RoomID != mxTestRoom || !validate {
		t.Fatalf("keep: %+v %v %v", cfg, validate, err)
	}
	// A new homeserver without a retyped token is refused before any call.
	if _, _, err := MergeMatrixUpdate(stored, MatrixUpdate{Server: "https://other.example.org", Enabled: true}); err == nil {
		t.Fatal("a server change kept the stored token")
	}
	if _, _, err := MergeMatrixUpdate(stored, MatrixUpdate{Server: "https://other.example.org", Token: " ", Enabled: true}); err == nil {
		t.Fatal("a whitespace token counted as retyped")
	}
	if _, v, err := MergeMatrixUpdate(stored, MatrixUpdate{Server: "https://other.example.org", Token: "syt_new", Enabled: true}); err != nil || !v {
		t.Fatalf("server change with a token: %v %v", v, err)
	}
	// Disabling with the same credentials needs no homeserver round trip.
	if _, v, err := MergeMatrixUpdate(stored, MatrixUpdate{Server: stored.Server, RoomID: stored.RoomID}); err != nil || v {
		t.Fatalf("disable: validate=%v err=%v", v, err)
	}
	// Enabling an empty channel is refused; saving it disabled clears it.
	if _, _, err := MergeMatrixUpdate(MatrixConfig{}, MatrixUpdate{Enabled: true}); err == nil {
		t.Fatal("enabled without credentials was accepted")
	}
	if _, v, err := MergeMatrixUpdate(MatrixConfig{}, MatrixUpdate{}); err != nil || v {
		t.Fatalf("clear: %v %v", v, err)
	}
}

// fakeMatrixHomeserver answers whoami, joined_members and send for
// mxTestToken, and records the send paths.
func fakeMatrixHomeserver(t *testing.T, failFirstSend int) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var sends []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+mxTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"unknown token"}`)
			return
		}
		p := r.URL.EscapedPath()
		switch {
		case p == "/_matrix/client/v3/account/whoami":
			_, _ = io.WriteString(w, `{"user_id":"`+mxTestUser+`"}`)
		case p == "/_matrix/client/v3/rooms/%21garbled/joined_members":
			_, _ = io.WriteString(w, `not json`)
		case p == "/_matrix/client/v3/rooms/%21dummyRoomId/joined_members":
			_, _ = io.WriteString(w, `{"joined":{"`+mxTestUser+`":{}}}`)
		case r.Method == http.MethodPut && strings.HasPrefix(p, "/_matrix/client/v3/rooms/%21dummyRoomId/send/m.room.message/"):
			var m matrixMessage
			_ = json.NewDecoder(r.Body).Decode(&m)
			mu.Lock()
			sends = append(sends, p+" "+m.MsgType)
			n := len(sends)
			mu.Unlock()
			if n <= failFirstSend {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"errcode":"M_LIMIT_EXCEEDED","error":"slow","retry_after_ms":10}`)
				return
			}
			_, _ = io.WriteString(w, `{"event_id":"$e"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sends...)
	}
}

func TestSendMatrixRetryReusesTheTransactionID(t *testing.T) {
	hs, sends := fakeMatrixHomeserver(t, 1)
	cfg := MatrixConfig{Server: hs.URL, RoomID: mxTestRoom, Token: mxTestToken, Enabled: true}
	if err := SendMatrix(cfg, "WAN down", "<b>WAN</b> down", true); err != nil {
		t.Fatal(err)
	}
	s := sends()
	if len(s) != 2 || s[0] != s[1] {
		t.Fatalf("the retry must reuse the transaction id: %v", s)
	}
	if !strings.HasSuffix(s[0], " m.text") {
		t.Fatalf("urgent alert msgtype: %v", s)
	}
	if err := SendMatrix(cfg, "new client", "", false); err != nil {
		t.Fatal(err)
	}
	if last := sends()[2]; !strings.HasSuffix(last, " m.notice") || strings.Fields(last)[0] == strings.Fields(s[0])[0] {
		t.Fatalf("second alert: %q (needs m.notice and a new transaction id)", last)
	}
}

func TestSendMatrixNoRetryOnUnauthorized(t *testing.T) {
	hs, sends := fakeMatrixHomeserver(t, 0)
	err := SendMatrix(MatrixConfig{Server: hs.URL, RoomID: mxTestRoom, Token: "syt_wrong"}, "x", "", true)
	if err == nil || len(sends()) != 0 || isRetryableMatrix(err) {
		t.Fatalf("err=%v sends=%v", err, sends())
	}
}

func TestValidateMatrix(t *testing.T) {
	hs, _ := fakeMatrixHomeserver(t, 0)
	cfg := MatrixConfig{Server: hs.URL, RoomID: mxTestRoom, Token: mxTestToken}
	if user, err := ValidateMatrix(cfg); err != nil || user != mxTestUser {
		t.Fatalf("validate = %q, %v", user, err)
	}
	cfg.RoomID = "!otherRoom"
	if _, err := ValidateMatrix(cfg); err == nil || !strings.Contains(err.Error(), "has not joined") {
		t.Fatalf("other room: %v", err)
	}
	cfg.RoomID = "!garbled"
	if _, err := ValidateMatrix(cfg); err == nil {
		t.Fatal("an unreadable joined_members answer passed validation")
	}
	cfg.RoomID, cfg.Token = mxTestRoom, "syt_wrong"
	if _, err := ValidateMatrix(cfg); err == nil || !strings.Contains(err.Error(), "refused the access token") {
		t.Fatalf("bad token: %v", err)
	}
}

func TestBuildMatrixMessage(t *testing.T) {
	m := buildMatrixMessage("🔴 NetGrip\nWAN down", "🔴 <b>NetGrip</b>\nWAN down", true)
	if m.MsgType != "m.text" || m.Body != "🔴 NetGrip\nWAN down" {
		t.Fatalf("message = %+v", m)
	}
	if m.Format != "org.matrix.custom.html" || m.FormattedBody != "🔴 <b>NetGrip</b><br>WAN down" {
		t.Fatalf("html = %+v", m)
	}
	long := buildMatrixMessage(strings.Repeat("é", 5000), strings.Repeat("é", 5000), false)
	if len(long.Body) > matrixMaxMsgLen || long.FormattedBody != "" || long.MsgType != "m.notice" {
		t.Fatalf("long: body %d bytes, html kept=%v, type %s", len(long.Body), long.FormattedBody != "", long.MsgType)
	}
}

func TestMatrixLogSafe(t *testing.T) {
	api := fmt.Errorf("wrapped: %w", &matrixAPIError{Status: 403, ErrCode: "M_FORBIDDEN", Message: "User @bot:example.org not in room !dummyRoomId:example.org"})
	if got := MatrixLogSafe(api); got != "status 403 M_FORBIDDEN" {
		t.Errorf("api = %q", got)
	}
	err := sendMatrixMessage(MatrixConfig{Server: "http://127.0.0.1:1", RoomID: mxTestRoom, Token: mxTestToken}, "txn", matrixMessage{MsgType: "m.text", Body: "x"})
	if got := MatrixLogSafe(err); got != "transport: connection refused" {
		t.Errorf("dial = %q (raw %v)", got, err)
	}
	if strings.Contains(err.Error(), "dummyRoomId") {
		t.Errorf("transport error carries the room id: %v", err)
	}
	dns := &matrixTransportError{err: &net.DNSError{Err: "no such host", Name: "matrix.example.org"}}
	if got := MatrixLogSafe(dns); got != "transport: dns lookup failed" {
		t.Errorf("dns = %q", got)
	}
}

func TestSendMatrixTestNeedsReadableEnabledConfig(t *testing.T) {
	if err := SendMatrixTest(MatrixConfig{Unreadable: true}); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("unreadable: %v", err)
	}
	if err := SendMatrixTest(MatrixConfig{Server: "https://matrix.example.org", RoomID: mxTestRoom, Token: mxTestToken}); err == nil {
		t.Fatal("a disabled channel sent a test")
	}
}
