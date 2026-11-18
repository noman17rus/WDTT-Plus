package main

func passwordDeviceIDs(entry *PasswordEntry) []string {
	if entry == nil {
		return nil
	}
	ids := make([]string, 0, len(entry.DeviceIDs)+1)
	seen := make(map[string]bool)
	for _, id := range append([]string{entry.DeviceID}, entry.DeviceIDs...) {
		if id != "" && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return ids
}

func passwordHasDevice(entry *PasswordEntry, deviceID string) bool {
	if entry == nil || deviceID == "" {
		return false
	}
	if entry.DeviceID == deviceID {
		return true
	}
	for _, id := range entry.DeviceIDs {
		if id == deviceID {
			return true
		}
	}
	return false
}

func forgetPasswordDevice(entry *PasswordEntry, deviceID string) {
	if entry == nil {
		return
	}
	if entry.DeviceID == deviceID {
		entry.DeviceID = ""
	}
	ids := entry.DeviceIDs[:0]
	for _, id := range entry.DeviceIDs {
		if id != deviceID {
			ids = append(ids, id)
		}
	}
	entry.DeviceIDs = ids
}

func snapshotDevices(snapshot adminLiveSnapshot) []*ClientDevice {
	if len(snapshot.devices) != 0 {
		return snapshot.devices
	}
	if snapshot.device != nil {
		return []*ClientDevice{snapshot.device}
	}
	return nil
}

func removeAdminSnapshotPeers(loaded *Database, snapshot adminLiveSnapshot, wgDev wgDevice) {
	for _, dev := range snapshotDevices(snapshot) {
		if shouldRemoveAdminSnapshotPeer(loaded, adminLiveSnapshot{password: snapshot.password, device: dev}) {
			removePeerFromWG(wgDev, dev)
		}
	}
}

func bindPasswordDevice(entry *PasswordEntry, deviceID string) bool {
	if entry == nil || deviceID == "" || passwordHasDevice(entry, deviceID) {
		return false
	}
	if entry.Shared {
		entry.DeviceIDs = append(entry.DeviceIDs, deviceID)
		return true
	}
	if entry.DeviceID != "" {
		return false
	}
	entry.DeviceID = deviceID
	return true
}
