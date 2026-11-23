package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The key is independent of VPN credentials and persists across server restarts.
func loadMonitoringKey(configDir string) ([]byte, error) {
	path := filepath.Join(configDir, "monitoring-id.key")
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("invalid monitoring ID key")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(key)
	closeErr := f.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	return key, closeErr
}

func monitoringID(key []byte, identity string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(identity))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

func metricQuote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(value) + `"`
}

type monitoringClient struct {
	id, name string
	down, up int64
	workers  int
}

func monitoringSnapshot(key []byte) ([]monitoringClient, error) {
	// Match admin's database -> runtime lock order. Holding both locks also
	// prevents a traffic flush from moving pending bytes between the two reads.
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	accessRuntimes.mu.Lock()
	defer accessRuntimes.mu.Unlock()
	clients := make(map[string]*monitoringClient, len(db.Passwords)+1)
	if db.MainPassword != "" {
		clients[db.MainPassword] = &monitoringClient{id: monitoringID(key, "owner"), name: "Владелец", down: db.AdminDownBytes, up: db.AdminUpBytes}
	}
	for password, entry := range db.Passwords {
		if entry == nil {
			continue
		}
		id := monitoringID(key, "client\x00"+password)
		name := entry.Label
		if name == "" {
			name = "Клиент " + id[:8]
		}
		clients[password] = &monitoringClient{id: id, name: name, down: entry.DownBytes, up: entry.UpBytes}
	}
	for _, item := range accessRuntimes.items {
		client := clients[item.identity.password]
		if client == nil {
			continue
		}
		client.down += item.pendingDown.Load()
		client.up += item.pendingUp.Load()
		// Retired workers may still be unwinding; do not count them online.
		for lease := range item.workers {
			if !lease.retired.Load() {
				client.workers++
			}
		}
	}
	result := make([]monitoringClient, 0, len(clients))
	for _, client := range clients {
		result = append(result, *client)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id < result[j].id })
	return result, nil
}

func monitoringHandler(key []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		clients, err := monitoringSnapshot(key)
		if err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintln(w, "# HELP vpn_client_traffic_bytes_total Client payload bytes, direction from client perspective.\n# TYPE vpn_client_traffic_bytes_total counter")
		fmt.Fprintln(w, "# HELP vpn_client_online Authenticated worker present (WDTT) or panel online status (VLESS).\n# TYPE vpn_client_online gauge")
		fmt.Fprintln(w, "# HELP vpn_client_workers Active authenticated WDTT workers.\n# TYPE vpn_client_workers gauge")
		fmt.Fprintln(w, "# HELP vpn_client_present Client exists in the source.\n# TYPE vpn_client_present gauge")
		for _, client := range clients {
			labels := `protocol="wdtt",client_id=` + metricQuote(client.id) + `,client_name=` + metricQuote(client.name)
			fmt.Fprintf(w, "vpn_client_present{%s} 1\n", labels)
			fmt.Fprintf(w, "vpn_client_traffic_bytes_total{%s,direction=\"down\"} %d\n", labels, client.down)
			fmt.Fprintf(w, "vpn_client_traffic_bytes_total{%s,direction=\"up\"} %d\n", labels, client.up)
			online := 0
			if client.workers > 0 {
				online = 1
			}
			fmt.Fprintf(w, "vpn_client_online{%s} %d\nvpn_client_workers{%s} %d\n", labels, online, labels, client.workers)
		}
		for name, value := range map[string]int64{
			"wdtt_server_connections":            int64(atomic.LoadInt32(&activeConns)),
			"wdtt_handshake_failures_total":      atomic.LoadInt64(&handshakeFailures),
			"wdtt_handshake_throttles_total":     atomic.LoadInt64(&handshakeThrottles),
			"wdtt_worker_limit_rejections_total": atomic.LoadInt64(&workerLimitRejections),
		} {
			kind := "counter"
			if name == "wdtt_server_connections" {
				kind = "gauge"
			}
			fmt.Fprintf(w, "# HELP %s WDTT server statistic.\n# TYPE %s %s\n%s %s\n", name, name, kind, name, strconv.FormatInt(value, 10))
		}
	})
	return mux
}

func startMetricsSocket(ctx context.Context, configDir, path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("metrics socket must have an absolute path")
	}
	if filepath.Clean(path) == filepath.Clean(adminSocketPath(configDir)) {
		return errors.New("metrics socket must differ from admin socket")
	}
	key, err := loadMonitoringKey(configDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// net.Listen refuses existing paths; never unlink arbitrary files or a live socket.
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		return err
	}
	server := &http.Server{Handler: monitoringHandler(key), ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second}
	context.AfterFunc(ctx, func() { server.Close() })
	go server.Serve(listener)
	return nil
}
