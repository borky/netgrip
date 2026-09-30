package modules

// FORK: logging in to a fleet peer's panel the way the panel expects.
//
// The fleet client posted {"password"} to /api/login, required 200 with a
// JSON token and sent it back as a Bearer header. The panel answers a login
// with 204 and a session cookie, and its API accepts only that cookie, so
// adopting or updating a peer always ended in "login failed", whatever the
// password.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
)

// fleetPanelLogin logs in to the panel at base as root and returns a copy of
// client that carries the session cookie on later requests.
func fleetPanelLogin(client *http.Client, base, password string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := *client
	c.Jar = jar

	body, _ := json.Marshal(map[string]string{"username": "root", "password": password})
	resp, err := c.Post(base+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("login: %v", err)
	}
	resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errors.New("login failed: the password was refused")
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, errors.New("login failed: too many attempts, the node is throttling logins")
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("login failed: HTTP %d", resp.StatusCode)
	}
	if len(jar.Cookies(resp.Request.URL)) == 0 {
		return nil, errors.New("login failed: the node answered without a session")
	}
	return &c, nil
}
