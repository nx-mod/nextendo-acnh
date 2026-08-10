package main

// Presence reporter: the server KNOWS who is online — every PID sending PRUDP packets is
// en train de jouer à Animal Crossing right now. We report the active PIDs to nextendo-account every 30s;
// it keeps them ONLINE via its TTL (90s) and serves them back to the Switch's friend list
// (nx-account) -> the friend shows as "online / playing Animal Crossing: New Horizons". This is the presence
// source that would otherwise be missing: the emulator fork only posts for the host of a
// private match, not for "online" in general.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const (
	presenceInterval = 30 * time.Second
	presenceTTL      = 60 * time.Second
	presenceStatus   = 2 // "playing"
)

var (
	presMu   sync.Mutex
	presSeen = map[uint64]time.Time{}
)

// notePresenceSeen records that a PID just sent a packet, i.e. it is online now.
func notePresenceSeen(pid uint64) {
	if pid == 0 {
		return
	}
	presMu.Lock()
	presSeen[pid] = time.Now()
	presMu.Unlock()
}

// activePIDs returns the PIDs seen within presenceTTL, dropping the stale ones so the
// account service lets them expire.
func activePIDs() []uint64 {
	now := time.Now()
	active := []uint64{}
	presMu.Lock()
	for pid, t := range presSeen {
		if now.Sub(t) < presenceTTL {
			active = append(active, pid)
		} else {
			delete(presSeen, pid)
		}
	}
	presMu.Unlock()
	return active
}

// startPresenceReporter POSTs the active PIDs to nextendo-account on a loop.
func startPresenceReporter() {
	base := envOr("NEXTENDO_ACCOUNT_URL", "http://nextendo-account:8080")
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		for {
			time.Sleep(presenceInterval)
			active := activePIDs()
			if len(active) == 0 {
				continue
			}
			body, err := json.Marshal(map[string]any{"appId": acnhAppID, "status": presenceStatus, "pids": active})
			if err != nil {
				continue
			}
			req, err := http.NewRequest("POST", base+"/internal/presence-batch", bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}()
}
