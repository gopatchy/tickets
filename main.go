package main

import (
	"log"
	"net/http"
)

func main() {
	http.Handle("/", http.FileServer(http.Dir("static")))

	log.Println("server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
