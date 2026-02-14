package handlers

import (
	"archive/zip"
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"k8s-blueprint/internal/generator"
	"k8s-blueprint/internal/models"
)

// NewRouter wires up all routes.
func NewRouter(staticFiles embed.FS) http.Handler {
	mux := http.NewServeMux()

	// Static assets
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("could not create static sub-fs: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Main UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		tmplFS, _ := fs.Sub(staticFiles, "templates")
		f, err := tmplFS.Open("index.html")
		if err != nil {
			http.Error(w, "template not found", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		var buf bytes.Buffer
		stat, _ := f.(fs.File)
		info, _ := stat.Stat()
		data := make([]byte, info.Size())
		f.Read(data)
		buf.Write(data)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(buf.Bytes())
	})

	// API: generate blueprint JSON
	mux.HandleFunc("/api/generate", generateHandler)

	// API: download zip
	mux.HandleFunc("/api/download", downloadHandler)

	return mux
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.BlueprintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		req.AppName = "my-app"
	}
	if req.Image == "" {
		req.Image = "nginx:1.25-alpine"
	}
	if req.Port == "" {
		req.Port = "8080"
	}

	var files []models.GeneratedFile
	if req.Mode == "kustomize" {
		files = generator.GenerateKustomize(req)
	} else {
		files = generator.GenerateHelm(req)
	}

	resp := models.BlueprintResponse{
		Files: files,
		Mode:  req.Mode,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.BlueprintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}

	if req.AppName == "" {
		req.AppName = "my-app"
	}
	if req.Image == "" {
		req.Image = "nginx:1.25-alpine"
	}
	if req.Port == "" {
		req.Port = "8080"
	}

	var files []models.GeneratedFile
	if req.Mode == "kustomize" {
		files = generator.GenerateKustomize(req)
	} else {
		files = generator.GenerateHelm(req)
	}

	// Build ZIP in memory
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	rootDir := req.AppName + "/"
	for _, f := range files {
		path := rootDir + f.Path
		// Ensure directory entries exist
		parts := strings.Split(f.Path, "/")
		if len(parts) > 1 {
			dirPath := rootDir + strings.Join(parts[:len(parts)-1], "/") + "/"
			_, _ = zw.Create(dirPath) // ignore error if already exists
		}
		fw, err := zw.Create(path)
		if err != nil {
			http.Error(w, "zip error", http.StatusInternalServerError)
			return
		}
		fw.Write([]byte(f.Content))
	}
	zw.Close()

	zipName := fmt.Sprintf("%s-%s-blueprint.zip", req.AppName, req.Mode)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zipName))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	w.Write(buf.Bytes())
}
