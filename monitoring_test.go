package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMonitoringKeyPersists(t *testing.T) {
	dir := t.TempDir()
	key, err := loadMonitoringKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadMonitoringKey(dir)
	if err != nil || string(key) != string(again) {
		t.Fatal("monitoring identity changed")
	}
	if monitoringID(key, "client") == monitoringID(key, "other") {
		t.Fatal("identities collide")
	}
	if err := os.WriteFile(filepath.Join(dir, "monitoring-id.key"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMonitoringKey(dir); err == nil {
		t.Fatal("accepted corrupt identity key")
	}
}

func TestMonitoringAggregatesWorkersAndPendingTrafficWithoutSecrets(t *testing.T) {
	previousDB, previousRuntimes := db, accessRuntimes
	t.Cleanup(func() { db = previousDB; accessRuntimes = previousRuntimes })
	db = &Database{MainPassword: "owner-secret", Passwords: map[string]*PasswordEntry{
		"private-password": {Label: "Phone\n\"test\"", DownBytes: 100, UpBytes: 200},
		"offline-password": {},
	}}
	accessRuntimes = newAccessRuntimeRegistry()
	for _, device := range []string{"device-a", "device-b"} {
		identity := accessIdentity{id: "test-client", password: "private-password", runtimeDevice: device}
		runtime, release, ok := acquireAccessWorker(identity)
		if !ok {
			t.Fatal("worker not admitted")
		}
		t.Cleanup(release)
		recordAccessTraffic(runtime, 10, 20)
	}
	key := []byte("test-key")
	clients, err := monitoringSnapshot(key)
	if err != nil {
		t.Fatal(err)
	}
	var client monitoringClient
	for _, entry := range clients {
		if entry.name == "Phone\n\"test\"" {
			client = entry
		}
	}
	if client.workers != 2 || client.down != 120 || client.up != 240 {
		t.Fatalf("wrong aggregate: %+v", client)
	}
	flushAccessTraffic()
	clients, err = monitoringSnapshot(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range clients {
		if entry.id == client.id && (entry.down != 120 || entry.up != 240) {
			t.Fatal("flush double counted traffic")
		}
	}
	w := httptest.NewRecorder()
	monitoringHandler(key).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, secret := range []string{"private-password", "offline-password", "owner-secret", "device-a", "device-b"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("exposed secret %s", secret)
		}
	}
	if !strings.Contains(w.Body.String(), `client_name="Phone\n\"test\""`) {
		t.Fatal("invalid metric escaping")
	}
	accessRuntimes.mu.Lock()
	for _, runtime := range accessRuntimes.items {
		for lease := range runtime.workers {
			lease.retired.Store(true)
		}
	}
	accessRuntimes.mu.Unlock()
	clients, _ = monitoringSnapshot(key)
	for _, entry := range clients {
		if entry.workers != 0 {
			t.Fatal("retired workers marked online")
		}
	}
}

func TestMonitoringSocketReadOnlyAndShutdown(t *testing.T) {
	previousDB := db
	db = &Database{}
	t.Cleanup(func() { db = previousDB })
	// Keep path short enough for Unix-domain sockets, including Windows AF_UNIX.
	dir, err := os.MkdirTemp("", "wdtt-metrics-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "m.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startMetricsSocket(ctx, dir, path); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, tc := range []struct {
		method, path string
		code         int
	}{{"GET", "/metrics", 200}, {"POST", "/metrics", 405}, {"GET", "/admin", 404}} {
		req, _ := http.NewRequest(tc.method, "http://wdtt"+tc.path, nil)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.code {
			t.Fatalf("%s %s: %d", tc.method, tc.path, response.StatusCode)
		}
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("socket remained after shutdown")
}

func TestMonitoringRefusesExistingFileAndAdminSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := startMetricsSocket(context.Background(), dir, path); err == nil {
		t.Fatal("replaced existing file")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep" {
		t.Fatal("existing file changed")
	}
	if err := startMetricsSocket(context.Background(), dir, adminSocketPath(dir)); err == nil {
		t.Fatal("accepted admin socket path")
	}
}
