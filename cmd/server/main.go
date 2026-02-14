package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"k8s-blueprint/internal/handlers"
)

//go:embed static templates
var staticFiles embed.FS

func main() {
	port := flag.String("port", getEnv("PORT", "8080"), "Server port")
	flag.Parse()

	mux := handlers.NewRouter(staticFiles)

	addr := fmt.Sprintf(":%s", *port)
	log.Printf("   KubeBlueprint running on http://localhost%s", addr)
	log.Printf("   Press Ctrl+C to stop\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
