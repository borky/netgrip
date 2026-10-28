package modules

// Matrix notification channel: alerts posted to a Matrix room by a bot
// account through the client-server API, next to Telegram and ntfy.
//
//	PUT {server}/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
//	Authorization: Bearer {token}
//
// The transaction id is fixed per alert and reused on the retry, so the
// homeserver drops the duplicate when the first attempt did land. The
// homeserver URL, the room id and the token are stored sealed (secretseal.go).

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// matrixConfigPath is a var (not const) so tests can point it at a temp dir.
var matrixConfigPath = "/etc/netgrip/matrix.json"

const (
	matrixSendTimeout   = 10 * time.Second
	matrixRetryWait     = 2 * time.Second
	matrixMaxRetryAfter = 5 * time.Second
	matrixMaxMsgLen     = 4096

	matrixFieldServer = "matrix.server"
	matrixFieldRoomID = "matrix.room_id"
	matrixFieldToken  = "matrix.token"
)

// matrixHTTPClient is a var so tests can swap it.
var matrixHTTPClient = &http.Client{Timeout: matrixSendTimeout}

var matrixTxnSeq atomic.Uint64

// MatrixConfig is the channel config in the clear. The token is write-only:
// it is never returned by the API.
type MatrixConfig struct {
	Server  string
	RoomID  string
	Token   string
	Enabled bool
	// Unreadable: sealed values are stored but the key does not open them
	// (lost or replaced). The channel acts as unconfigured until the
	// credentials are entered again.
	Unreadable bool
}

// matrixFile is the on-disk shape: every credential sealed.
type matrixFile struct {
	Server  string `json:"server"`
	RoomID  string `json:"roomId"`
	Token   string `json:"token"`
	Enabled bool   `json:"enabled"`
}

// Configured reports whether every field a send needs is present.
func (c MatrixConfig) Configured() bool {
	return c.Server != "" && c.RoomID != "" && c.Token != ""
}

func LoadMatrixConfig() MatrixConfig {
	data, err := os.ReadFile(matrixConfigPath)
	if err != nil {
		return MatrixConfig{}
	}
	var f matrixFile
	if json.Unmarshal(data, &f) != nil {
		// A damaged file is reported, not mistaken for "never configured".
		return MatrixConfig{Unreadable: true}
	}
	cfg := MatrixConfig{Enabled: f.Enabled}
	for _, fld := range []struct {
		name, stored string
		dst          *string
	}{
		{matrixFieldServer, f.Server, &cfg.Server},
		{matrixFieldRoomID, f.RoomID, &cfg.RoomID},
		{matrixFieldToken, f.Token, &cfg.Token},
	} {
		v, err := unsealSecret(fld.name, fld.stored)
		if err != nil {
			cfg.Unreadable = true
			continue
		}
		*fld.dst = v
	}
	if cfg.Unreadable {
		cfg.Server, cfg.RoomID, cfg.Token = "", "", ""
	}
	return cfg
}

// NormalizeMatrixConfig trims the fields and checks their shape. All three
// empty means "clear the channel" and is valid.
func NormalizeMatrixConfig(cfg MatrixConfig) (MatrixConfig, error) {
	cfg.Server = strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	cfg.RoomID = strings.TrimSpace(cfg.RoomID)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Server == "" && cfg.RoomID == "" && cfg.Token == "" {
		return cfg, nil
	}
	if !cfg.Configured() {
		return cfg, errors.New("homeserver URL, room id and access token are all required")
	}
	u, err := url.Parse(cfg.Server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return cfg, errors.New("homeserver must be an http(s) URL, e.g. https://matrix.example.org")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return cfg, errors.New("homeserver URL must not carry credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !matrixPlainHTTPAllowed(u.Hostname()) {
		return cfg, errors.New("use https: the access token would cross the network in the clear (plain http is accepted only for localhost or a private address)")
	}
	if !strings.HasPrefix(cfg.RoomID, "!") || strings.ContainsAny(cfg.RoomID, " \t\r\n/") {
		return cfg, errors.New("room id must start with ! (an alias such as #room:server is not a room id)")
	}
	if strings.ContainsAny(cfg.Token, " \t\r\n") {
		return cfg, errors.New("access token must not contain whitespace")
	}
	return cfg, nil
}

// matrixPlainHTTPAllowed: http only where the token stays on the host or
// the local network.
func matrixPlainHTTPAllowed(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// SaveMatrixConfig normalizes, seals and persists the config.
func SaveMatrixConfig(cfg MatrixConfig) error {
	cfg, err := NormalizeMatrixConfig(cfg)
	if err != nil {
		return err
	}
	f := matrixFile{Enabled: cfg.Enabled}
	for _, fld := range []struct {
		name, val string
		dst       *string
	}{
		{matrixFieldServer, cfg.Server, &f.Server},
		{matrixFieldRoomID, cfg.RoomID, &f.RoomID},
		{matrixFieldToken, cfg.Token, &f.Token},
	} {
		sealed, err := sealSecret(fld.name, fld.val)
		if err != nil {
			return fmt.Errorf("seal: %w", err)
		}
		*fld.dst = sealed
	}
	if err := os.MkdirAll(filepath.Dir(matrixConfigPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Temp file + rename, created 0600: a crash mid-write leaves the old
	// config, not a half-written one. There is no fsync, so a power cut can
	// still leave an empty file; that loads as Unreadable, not as "never
	// configured".
	return writeFileAtomic(matrixConfigPath, data)
}

// matrixMessage is the m.room.message content.
type matrixMessage struct {
	MsgType       string `json:"msgtype"`
	Body          string `json:"body"`
	Format        string `json:"format,omitempty"`
	FormattedBody string `json:"formatted_body,omitempty"`
}

// buildMatrixMessage takes the plain text and the already-escaped HTML the
// monitor builds for ntfy and Telegram. Urgent alerts are m.text; the rest
// are m.notice, which clients show without a sound (Telegram's silent
// messages).
func buildMatrixMessage(plain, html string, urgent bool) matrixMessage {
	m := matrixMessage{MsgType: "m.notice", Body: plain}
	if urgent {
		m.MsgType = "m.text"
	}
	if len(m.Body) > matrixMaxMsgLen {
		m.Body = truncateUTF8(m.Body, matrixMaxMsgLen-3) + "..."
	}
	// Dropped, not cut, when too long: a cut could leave an open tag.
	if html != "" {
		if h := strings.ReplaceAll(html, "\n", "<br>"); len(h) <= matrixMaxMsgLen {
			m.Format, m.FormattedBody = "org.matrix.custom.html", h
		}
	}
	return m
}

func newMatrixTxnID() string {
	return fmt.Sprintf("netgrip-%d-%d", time.Now().UnixNano(), matrixTxnSeq.Add(1))
}

// SendMatrix posts one alert. Synchronous like ntfy (the monitor is low
// frequency): a 10 s timeout and at most one retry, with the same
// transaction id, on a 5xx, a 429 or a transient network error.
func SendMatrix(cfg MatrixConfig, plain, html string, urgent bool) error {
	if !cfg.Configured() {
		return errors.New("homeserver URL, room id and access token are required")
	}
	m := buildMatrixMessage(plain, html, urgent)
	txn := newMatrixTxnID()
	err := sendMatrixMessage(cfg, txn, m)
	if err == nil || !isRetryableMatrix(err) {
		return err
	}
	wait := matrixRetryWait
	var ae *matrixAPIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		wait = min(ae.RetryAfter, matrixMaxRetryAfter)
	}
	time.Sleep(wait)
	return sendMatrixMessage(cfg, txn, m)
}

// SendMatrixTest posts a test message with the saved config. Like the send
// path it requires the channel to be enabled.
func SendMatrixTest(cfg MatrixConfig) error {
	if cfg.Unreadable {
		return errors.New("the stored Matrix credentials cannot be decrypted: enter them again")
	}
	if !cfg.Enabled {
		return errors.New("Matrix channel is disabled")
	}
	return SendMatrix(cfg, "✅ NetGrip Matrix notifications configured correctly.", "", true)
}

// matrixRoomPath escapes a room id as one path segment: ! becomes %21, and
// the colon of a :server part is escaped too.
func matrixRoomPath(roomID string) string {
	return strings.ReplaceAll(url.PathEscape(roomID), ":", "%3A")
}

func sendMatrixMessage(cfg MatrixConfig, txn string, m matrixMessage) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	u := cfg.Server + "/_matrix/client/v3/rooms/" + matrixRoomPath(cfg.RoomID) +
		"/send/m.room.message/" + url.PathEscape(txn)
	_, err = matrixDo(http.MethodPut, u, cfg.Token, body)
	return err
}

// matrixAPIError is a non-2xx answer from the homeserver.
type matrixAPIError struct {
	Status     int
	ErrCode    string
	Message    string
	RetryAfter time.Duration
}

func (e *matrixAPIError) Error() string {
	if e.ErrCode != "" {
		return fmt.Sprintf("status %d: %s: %s", e.Status, e.ErrCode, e.Message)
	}
	return fmt.Sprintf("status %d: %s", e.Status, e.Message)
}

// matrixTransportError drops the request URL from a client error: it
// carries the room id, which is stored sealed.
type matrixTransportError struct{ err error }

func (e *matrixTransportError) Error() string {
	var ue *url.Error
	if errors.As(e.err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return e.err.Error()
}
func (e *matrixTransportError) Unwrap() error { return e.err }

// matrixDo runs one authenticated call and returns the body of a 2xx answer.
func matrixDo(method, u, token string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), matrixSendTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, &matrixTransportError{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := matrixHTTPClient.Do(req)
	if err != nil {
		return nil, &matrixTransportError{err: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}
	ae := &matrixAPIError{Status: resp.StatusCode}
	var mErr struct {
		ErrCode      string `json:"errcode"`
		Error        string `json:"error"`
		RetryAfterMs int64  `json:"retry_after_ms"`
	}
	if json.Unmarshal(respBody, &mErr) == nil && (mErr.ErrCode != "" || mErr.Error != "") {
		ae.ErrCode, ae.Message = mErr.ErrCode, mErr.Error
	} else {
		ae.Message = truncateUTF8(strings.TrimSpace(string(respBody)), 200)
	}
	if mErr.RetryAfterMs > 0 {
		ae.RetryAfter = time.Duration(mErr.RetryAfterMs) * time.Millisecond
	} else if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		ae.RetryAfter = time.Duration(secs) * time.Second
	}
	return nil, ae
}

func isRetryableMatrix(err error) bool {
	if err == nil {
		return false
	}
	var ae *matrixAPIError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	for _, target := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, io.ErrUnexpectedEOF} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// MatrixLogSafe renders err for the log. The homeserver's error text can
// name the room and DNS/TLS errors name the host, both stored sealed: keep
// the status, the errcode and the kind of failure only. The full text still
// goes back to the admin from the save and test endpoints.
func MatrixLogSafe(err error) string {
	if err == nil {
		return ""
	}
	var ae *matrixAPIError
	if errors.As(err, &ae) {
		if ae.ErrCode != "" {
			return fmt.Sprintf("status %d %s", ae.Status, ae.ErrCode)
		}
		return fmt.Sprintf("status %d", ae.Status)
	}
	var te *matrixTransportError
	if !errors.As(err, &te) {
		return err.Error() // our own messages carry no secrets
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return "transport: dns lookup failed"
	case errors.As(err, &certErr):
		return "transport: tls certificate rejected"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "transport: timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "transport: connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "transport: connection reset"
	default:
		return "transport: request failed"
	}
}

// ValidateMatrix checks the token with whoami and that its user has joined
// the room, and returns the bot's user id.
func ValidateMatrix(cfg MatrixConfig) (string, error) {
	raw, err := matrixDo(http.MethodGet, cfg.Server+"/_matrix/client/v3/account/whoami", cfg.Token, nil)
	if err != nil {
		var ae *matrixAPIError
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			return "", fmt.Errorf("the homeserver refused the access token (%s)", ae.ErrCode)
		}
		return "", fmt.Errorf("whoami: %w", err)
	}
	var who struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(raw, &who); err != nil || who.UserID == "" {
		return "", errors.New("whoami: the answer carries no user id - is this a Matrix homeserver?")
	}
	notJoined := fmt.Errorf("%s has not joined that room: invite it and accept the invite first", who.UserID)
	raw, err = matrixDo(http.MethodGet, cfg.Server+"/_matrix/client/v3/rooms/"+matrixRoomPath(cfg.RoomID)+"/joined_members", cfg.Token, nil)
	if err != nil {
		var ae *matrixAPIError
		if errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound) {
			return who.UserID, notJoined
		}
		return who.UserID, fmt.Errorf("joined_members: %w", err)
	}
	var members struct {
		Joined map[string]json.RawMessage `json:"joined"`
	}
	if err := json.Unmarshal(raw, &members); err != nil || members.Joined == nil {
		return who.UserID, errors.New("joined_members: the homeserver's answer could not be read")
	}
	if _, ok := members.Joined[who.UserID]; !ok {
		return who.UserID, notJoined
	}
	return who.UserID, nil
}

// MatrixUpdate is a save request from the panel. A blank field keeps the
// stored value.
type MatrixUpdate struct {
	Server, RoomID, Token string
	Enabled               bool
}

// MergeMatrixUpdate applies an update to the stored config and checks it.
// validate reports whether the result must be checked against the
// homeserver before it is saved: it is complete and either enabled or
// carries new credentials. An incomplete result is valid only as a
// disabled, cleared channel.
func MergeMatrixUpdate(stored MatrixConfig, upd MatrixUpdate) (cfg MatrixConfig, validate bool, err error) {
	cfg = stored
	cfg.Unreadable = false
	if upd.Server != "" {
		cfg.Server = upd.Server
	}
	if upd.RoomID != "" {
		cfg.RoomID = upd.RoomID
	}
	if upd.Token != "" {
		cfg.Token = upd.Token
	}
	cfg.Enabled = upd.Enabled
	cfg, err = NormalizeMatrixConfig(cfg)
	if err != nil {
		return cfg, false, err
	}
	if !cfg.Configured() {
		if cfg.Enabled {
			return cfg, false, errors.New("homeserver URL, room id and access token are required")
		}
		return cfg, false, nil
	}
	// The stored token only ever goes to the homeserver it was entered for:
	// a new URL needs the token typed again, or validation would hand the
	// stored one to that server.
	if stored.Server != "" && cfg.Server != stored.Server && strings.TrimSpace(upd.Token) == "" {
		return cfg, false, errors.New("enter the access token again to change the homeserver")
	}
	// Turning the channel off with the same credentials needs no round trip:
	// an unreachable homeserver must not keep it from being disabled.
	changed := cfg.Server != stored.Server || cfg.RoomID != stored.RoomID || cfg.Token != stored.Token
	return cfg, cfg.Enabled || changed, nil
}
