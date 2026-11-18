package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestSharedAdminCreationAndUnbinding(t *testing.T) {
	loaded := &Database{MainPassword: "owner", MaxPasswords: 10, DefaultPorts: "56000,56001,9000", Passwords: map[string]*PasswordEntry{}, Devices: map[string]*ClientDevice{}}
	hashes := "abcdefghijklmnop,qrstuvwxyzABCDEF,GHIJKLMNOPQRSTUV,WXYZabcdefghijkl"
	dir := t.TempDir()
	response, err := adminCreatePassword(dir, loaded, []string{"--shared", "--days", "0", "--vk-hash", hashes})
	if err != nil {
		t.Fatal(err)
	}
	password := response.Password.Password
	entry := loaded.Passwords[password]
	if !entry.Shared || entry.VkHash != hashes {
		t.Fatal("shared mode or four calls lost")
	}
	for _, id := range []string{"one", "two"} {
		bindPasswordDevice(entry, id)
		loaded.Devices[id] = &ClientDevice{DeviceID: id, IP: "10.66.66.2"}
	}
	info := buildAdminPasswordInfo(loaded, password, entry)
	if !info.Shared || len(info.Devices) != 2 || buildAdminServerInfo(dir, loaded).OrphanDeviceCount != 0 {
		t.Fatal("shared devices reported as orphans")
	}
	raw, err := encodeClientTransfer(password, entry)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := decodeClientTransfer(raw)
	if err != nil || !imported.Shared || imported.VkHash != hashes {
		t.Fatal("transfer lost shared mode", err)
	}
	if _, err = adminUnbindPassword(dir, loaded, []string{"--password", password}); err != nil {
		t.Fatal(err)
	}
	if len(passwordDeviceIDs(entry)) != 0 || len(loaded.Devices) != 0 || !entry.Shared {
		t.Fatal("unbind did not clear all devices while retaining shared mode")
	}
}
func TestDeviceIPPoolContinuesPastLegacySubnet(t *testing.T) {
	previous := db
	defer func() { db = previous }()
	db = &Database{Devices: map[string]*ClientDevice{}}
	for i := 2; i <= 250; i++ {
		id := fmt.Sprint(i)
		db.Devices[id] = &ClientDevice{IP: fmt.Sprintf("10.66.66.%d", i)}
	}
	ip := getNextIP()
	if ip == "" || strings.HasPrefix(ip, "10.66.66.") {
		t.Fatalf("legacy subnet still caps users: %q", ip)
	}
	if ip != "10.66.67.2" {
		t.Fatal("unexpected next address", ip)
	}
}
