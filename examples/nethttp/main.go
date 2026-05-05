package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/acrossed/acrossed-go"
)

func main() {
	client, err := acrossed.New(acrossed.Config{
		APIKey:        os.Getenv("ACROSSED_KEY"),
		SigningSecret: os.Getenv("ACROSSED_SECRET"),
		Timeout:       2 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}

	gate := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, _ := client.CheckHTTP(r.Context(), r)
			if d.Deny() {
				http.Error(w, "blocked: "+d.Reason, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello, protected world"))
	})
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", gate(mux)))
}
