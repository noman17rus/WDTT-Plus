package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
	"wdtt.local/pathprobe"
)

type sharedTestConn struct{ closed atomic.Bool }

func (c *sharedTestConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *sharedTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *sharedTestConn) Close() error                     { c.closed.Store(true); return nil }
func (c *sharedTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *sharedTestConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *sharedTestConn) SetDeadline(time.Time) error      { c.closed.Store(true); return nil }
func (c *sharedTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sharedTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestSharedAccessHasNoSingleDeviceBindingLimit(t *testing.T) {
	entry := &PasswordEntry{Shared: true}
	for i := 0; i < 1000; i++ {
		if !bindPasswordDevice(entry, fmt.Sprintf("phone-%d", i)) {
			t.Fatal("shared binding rejected", i)
		}
	}
	if bindPasswordDevice(entry, "phone-0") || len(passwordDeviceIDs(entry)) != 1000 {
		t.Fatal("duplicate binding or truncated device list")
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var restored PasswordEntry
	if err = json.Unmarshal(raw, &restored); err != nil || !restored.Shared || !passwordHasDevice(&restored, "phone-999") {
		t.Fatal("shared bindings did not persist", err)
	}
	forgetPasswordDevice(&restored, "phone-0")
	if passwordHasDevice(&restored, "phone-0") || !passwordHasDevice(&restored, "phone-999") {
		t.Fatal("removing one device changed other bindings")
	}
	single := &PasswordEntry{}
	if !bindPasswordDevice(single, "first") || bindPasswordDevice(single, "second") || single.DeviceID != "first" {
		t.Fatal("legacy single-device binding changed")
	}
}

func TestSharedAccessSessionsAndWorkerSlotsAreIndependent(t *testing.T) {
	previous := accessRuntimes
	accessRuntimes = newAccessRuntimeRegistry()
	t.Cleanup(func() { accessRuntimes = previous })
	configureAccessRuntime(1, 0)
	var runtimes []*accessRuntime
	var connections []*sharedTestConn
	for i := 0; i < 40; i++ {
		device := fmt.Sprintf("phone-%d", i)
		identity := accessIdentity{id: "pass:shared", password: "shared-password", runtimeDevice: device}
		conn := &sharedTestConn{}
		runtime, _, release, ok := acquireAccessWorkerForSession(identity, conn, device, "same-session-0001", pathprobe.Worker{Slot: 1, Attempt: 1})
		if !ok {
			t.Fatal("another device consumed this device's worker quota", i)
		}
		t.Cleanup(release)
		runtimes = append(runtimes, runtime)
		connections = append(connections, conn)
	}
	first := accessIdentity{id: "pass:shared", password: "shared-password", runtimeDevice: "phone-0"}
	if _, _, release, ok := acquireAccessWorkerForSession(first, &sharedTestConn{}, "phone-0", "same-session-0001", pathprobe.Worker{Slot: 2, Attempt: 1}); ok {
		release()
		t.Fatal("per-device worker quota ignored")
	}
	_, _, release, ok := acquireAccessWorkerForSession(first, &sharedTestConn{}, "phone-0", "new-session-00002", pathprobe.Worker{Slot: 1, Attempt: 1})
	if !ok {
		t.Fatal("reconnect failed")
	}
	defer release()
	if !connections[0].closed.Load() {
		t.Fatal("previous generation for the same device survived")
	}
	for i := 1; i < len(connections); i++ {
		if connections[i].closed.Load() || runtimes[i] == runtimes[0] {
			t.Fatal("reconnect displaced another device", i)
		}
	}
}

func TestSharedAccessRevocationAppliesToEveryDevice(t *testing.T) {
	previous := db
	t.Cleanup(func() { db = previous })
	entry := &PasswordEntry{Shared: true, DeviceIDs: []string{"one", "two"}}
	db = &Database{Passwords: map[string]*PasswordEntry{"shared": entry}}
	for _, device := range entry.DeviceIDs {
		identity := accessIdentity{id: "pass:shared", password: "shared", runtimeDevice: device}
		if currentAccessIdentityState(identity) != accessIdentityActive {
			t.Fatal("bound device rejected")
		}
		entry.IsDeactivated = true
		if currentAccessIdentityState(identity) != accessIdentityDeactivated {
			t.Fatal("deactivation ignored")
		}
		entry.IsDeactivated = false
		entry.ExpiresAt = time.Now().Unix() - 1
		if currentAccessIdentityState(identity) != accessIdentityExpired {
			t.Fatal("expiry ignored")
		}
		entry.ExpiresAt = 0
	}
	forgetPasswordDevice(entry, "one")
	if currentAccessIdentityState(accessIdentity{id: "pass:shared", password: "shared", runtimeDevice: "one"}) != accessIdentityUnknown {
		t.Fatal("unbound device still authorized")
	}
	if currentAccessIdentityState(accessIdentity{id: "pass:shared", password: "shared", runtimeDevice: "two"}) != accessIdentityActive {
		t.Fatal("unbinding one device revoked another")
	}
	delete(db.Passwords, "shared")
	if currentAccessIdentityState(accessIdentity{id: "pass:shared", password: "shared", runtimeDevice: "two"}) != accessIdentityUnknown {
		t.Fatal("deleted access still authorized")
	}
}
