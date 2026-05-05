// Package acrossed is the official Go SDK for the Acrossed rule enforcement engine.
//
// Usage:
//
//	client, err := acrossed.New(acrossed.Config{
//	    APIKey:        "ack_live_...",
//	    SigningSecret: "acsk_...",
//	})
//	if err != nil { log.Fatal(err) }
//	d, err := client.Check(ctx, acrossed.Request{
//	    IP: "1.2.3.4", Method: "GET", Path: "/login",
//	    Headers: map[string]string{"user-agent": "curl"},
//	})
//	if d.Deny() { http.Error(w, d.Reason, 403); return }
package acrossed

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const DefaultBaseURL = "https://api.acrossed.com"

// Config configures a new Client.
type Config struct {
	APIKey        string        // ack_live_… (required)
	SigningSecret string        // acsk_…    (required)
	BaseURL       string        // optional override; defaults to https://api.acrossed.com
	Timeout       time.Duration // per-request timeout; defaults to 2s
	FailClosed    bool          // if true, transport errors deny instead of allow
	HTTPClient    *http.Client  // optional custom client (e.g. for connection pooling)
}

// Client is safe for concurrent use across goroutines.
type Client struct {
	apiKey     string
	secret     []byte
	base       string
	failClosed bool
	http       *http.Client
}

// New constructs a Client and validates the credentials' shape.
func New(c Config) (*Client, error) {
	if !strings.HasPrefix(c.APIKey, "ack_") {
		return nil, errors.New("acrossed: APIKey must start with ack_")
	}
	if !strings.HasPrefix(c.SigningSecret, "acsk_") {
		return nil, errors.New("acrossed: SigningSecret must start with acsk_")
	}
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	return &Client{
		apiKey:     c.APIKey,
		secret:     []byte(c.SigningSecret),
		base:       strings.TrimRight(base, "/"),
		failClosed: c.FailClosed,
		http:       httpClient,
	}, nil
}

// Request describes the inbound HTTP request you want to evaluate.
type Request struct {
	IP      string            `json:"ip"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Query   map[string]string `json:"query"`
}

// Decision is the engine's verdict.
type Decision struct {
	Decision    string `json:"decision"`            // "allow" | "deny"
	Reason      string `json:"reason"`              // e.g. "no_rule_matched"
	MatchedRule string `json:"matchedRule,omitempty"`
	LatencyUS   int    `json:"latencyUs,omitempty"`
}

// Allow returns true when the engine permitted the request.
func (d Decision) Allow() bool { return d.Decision == "allow" }

// Deny returns true when the engine blocked the request.
func (d Decision) Deny() bool { return d.Decision == "deny" }

// Check evaluates a request against your project's rules.
func (c *Client) Check(ctx context.Context, r Request) (Decision, error) {
	if r.Headers == nil {
		r.Headers = map[string]string{}
	}
	if r.Query == nil {
		r.Query = map[string]string{}
	}
	if r.Method == "" {
		r.Method = "GET"
	}
	if r.Path == "" {
		r.Path = "/"
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Decision{}, fmt.Errorf("acrossed: marshal: %w", err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, "POST", c.base+"/check", bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("acrossed: new request: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-acrossed-key", c.apiKey)
	req.Header.Set("x-acrossed-timestamp", ts)
	req.Header.Set("x-acrossed-signature", sig)

	resp, err := c.http.Do(req)
	if err != nil {
		if c.failClosed {
			return Decision{Decision: "deny", Reason: "transport_error"}, err
		}
		return Decision{Decision: "allow", Reason: "fail_open"}, nil
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return Decision{Decision: "deny", Reason: "invalid_response"}, err
	}
	return d, nil
}

// CheckHTTP is a convenience helper that builds a Request from a stdlib *http.Request
// and evaluates it. Use this from net/http or chi/gin/echo middleware.
func (c *Client) CheckHTTP(ctx context.Context, r *http.Request) (Decision, error) {
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	query := make(map[string]string)
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			query[k] = v[0]
		}
	}
	ip := r.Header.Get("X-Forwarded-For")
	if i := strings.IndexByte(ip, ','); i >= 0 {
		ip = strings.TrimSpace(ip[:i])
	}
	if ip == "" {
		ip = r.RemoteAddr
		if i := strings.LastIndexByte(ip, ':'); i >= 0 {
			ip = ip[:i]
		}
	}
	return c.Check(ctx, Request{
		IP:      ip,
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: headers,
		Query:   query,
	})
}

// Middleware returns a net/http middleware that gates every incoming request.
// Denied requests receive a 403 JSON response; the next handler is not called.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := c.CheckHTTP(r.Context(), r)
		if d.Deny() {
			w.Header().Set(content-type, application/json)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, , d.Reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}
