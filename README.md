# acrossed-go — Go SDK

Sub-millisecond rule enforcement for net/http, Gin, Echo, and any Go HTTP framework.

## Install

```bash
go get github.com/acrossed-com/sdk-go
```

## Quick start

```go
client, err := acrossed.New(acrossed.Config{
    APIKey:        os.Getenv("ACROSSED_KEY"),
    SigningSecret: os.Getenv("ACROSSED_SECRET"),
})
if err != nil { log.Fatal(err) }

d, _ := client.Check(ctx, acrossed.Request{
    IP: "1.2.3.4", Method: "GET", Path: "/login",
})
if d.Deny() { http.Error(w, "blocked", 403); return }
```

## net/http — one-liner middleware

```go
http.ListenAndServe(":8080", client.Middleware(myMux))
```

## CheckHTTP — from *http.Request

```go
func gate(c *acrossed.Client, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        d, _ := c.CheckHTTP(r.Context(), r)
        if d.Deny() { http.Error(w, d.Reason, 403); return }
        next.ServeHTTP(w, r)
    })
}
```

## Gin middleware

```go
func AcrossedGin(c *acrossed.Client) gin.HandlerFunc {
    return func(ctx *gin.Context) {
        d, _ := c.CheckHTTP(ctx.Request.Context(), ctx.Request)
        if d.Deny() { ctx.AbortWithStatusJSON(403, gin.H{"error": d.Reason}); return }
        ctx.Next()
    }
}
```

Fails **open** by default. Set `Config.FailClosed = true` for stricter postures.
