package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
)

type ProxyService struct {
	domains map[string]string
	cons    map[string]http.Client
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevelFromEnv(),
	})))

	addr := "127.0.0.1:3000"
	domain := "RezaDarius.de"
	target := "/tmp/darius_art.sock"

	proxy := ProxyService{
		domains: map[string]string{
			domain: target,
		},
		cons: map[string]http.Client{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxy.ProxyHandle)

	fmt.Printf("listening on %v", addr)

	log.Fatal(http.ListenAndServeTLS(
		addr,
		"example_cert.pem",
		"example_key.pem",
		mux,
	))
}

func (p *ProxyService) ProxyHandle(w http.ResponseWriter, r *http.Request) {
	request_host := r.Host
	if request_host == "" {
		slog.Debug("no host found on request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	host, ok := p.domains[r.Host]
	if !ok {
		slog.Debug("host not found")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if host == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	backend := p.DialBackend(host)

	uri := r.RequestURI
	slog.Debug("request URI:", "uri", uri)

	// forward method, headers, and body
	backendReq, _ := http.NewRequest(r.Method, "http://unix"+r.RequestURI, r.Body)
	backendReq.Header = r.Header.Clone() // independent copy

	stripHeaders(backendReq.Header)

	resp, err := backend.Do(backendReq)
	if err != nil {
		slog.Debug("error when sending to backend:", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// copy response headers
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	return
}

func (p *ProxyService) DialBackend(host string) http.Client {
	slog.Debug("connecting to:", "host", host)
	if client, ok := p.cons[host]; ok {
		return client
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", host)
			},
		},
	}
	p.cons[host] = client
	return client

}

func logLevelFromEnv() slog.Level {
	switch strings.ToLower(os.Getenv("GO_LOG")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func stripHeaders(h http.Header) {
	hopByHop := []string{
		"Connection",
		"Transfer-Encoding",
		"Te",
		"Trailer",
		"Upgrade",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
	}
	for _, header := range hopByHop {
		h.Del(header)
	}
}
