package main

// Source de la liste d'amis pour les données de notification (0x6D méthodes 9 / 10 / 13).
//
// C'est ce qui remplit le menu « rendre visite à un ami » : Rounard ne propose que les amis
// ayant publié une donnée de notification (porte ouverte). Sans liste d'amis, la réponse est
// vide et le jeu annonce qu'aucune île n'est accessible — même quand des amis en ont ouvert une.
//
// Le graphe d'amitié appartient déjà à nextendo-account, qui l'expose sur
// GET /internal/identity?pid=X -> {"friends":[{"pid":...},...]}. On s'y branche sans rien
// changer au service partagé, avec un cache court car le matchmaking interroge souvent.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

const friendCacheTTL = 30 * time.Second

var (
	friendMu     sync.Mutex
	friendCache  = map[uint64]friendEntry{}
	friendClient = &http.Client{Timeout: 3 * time.Second}
)

type friendEntry struct {
	pids []uint64
	at   time.Time
}

func accountBase() string {
	return envOr("NEXTENDO_ACCOUNT_URL", "http://nextendo-account:8080")
}

// acnhFriendPIDs renvoie les PID des amis acceptés de pid.
//
// Tolérant à la panne : toute erreur renvoie nil (« aucun ami ce tour-ci ») plutôt qu'un
// blocage. Un service de comptes momentanément injoignable doit vider le menu de visite,
// pas figer le matchmaking.
func acnhFriendPIDs(pid uint64) []uint64 {
	friendMu.Lock()
	if e, ok := friendCache[pid]; ok && time.Since(e.at) < friendCacheTTL {
		pids := e.pids
		friendMu.Unlock()
		return pids
	}
	friendMu.Unlock()

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/internal/identity?pid=%d", accountBase(), pid), nil)
	if err != nil {
		return nil
	}
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" {
		req.Header.Set("X-Internal-Key", k)
	}
	resp, err := friendClient.Do(req)
	if err != nil {
		fmt.Printf("[ACNH amis] pid=%d : service de comptes injoignable (%v)\n", pid, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[ACNH amis] pid=%d : /internal/identity a répondu %d\n", pid, resp.StatusCode)
		return nil
	}

	var out struct {
		Friends []struct {
			PID uint64 `json:"pid"`
		} `json:"friends"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	pids := make([]uint64, 0, len(out.Friends))
	for _, f := range out.Friends {
		pids = append(pids, f.PID)
	}

	friendMu.Lock()
	friendCache[pid] = friendEntry{pids: pids, at: time.Now()}
	friendMu.Unlock()

	fmt.Printf("[ACNH amis] pid=%d -> %d ami(s)\n", pid, len(pids))
	return pids
}
