# Acrossed — Go SDK

Sub-millisecond rule enforcement for any Go backend.

## Install

```bash
go get github.com/acrossed/acrossed-go
```

## Quick start

```go
client, _ := acrossed.New(acrossed.Config{
    APIKey:        "ack_live_...",
    SigningSecret: "acsk_...",
})

d, err := client.Check(ctx, acrossed.Request{
    IP: "1.2.3.4", Method: "GET", Path: "/login",
    Headers: map[string]string{"user-agent": "curl"},
})
if d.Deny() { http.Error(w, d.Reason, 403); return }
```

## net/http middleware

```go
func gate(c *acrossed.Client, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        d, _ := c.CheckHTTP(r.Context(), r)
        if d.Deny() { http.Error(w, "blocked: "+d.Reason, 403); return }
        next.ServeHTTP(w, r)
    })
}
```

## Failure mode

By default the SDK fails **open** — if the Acrossed API is unreachable, requests are allowed through. Set `Config.FailClosed = true` to invert.
