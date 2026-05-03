package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/acrossed-com/sdk-go"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello, protected world")
	})

	// Wrap the entire mux with the Acrossed middleware.
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", client.Middleware(mux)))
}
