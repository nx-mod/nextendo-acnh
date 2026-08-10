package main

// Méthodes que le protocole NEX standard ne définit pas mais qu'Animal Crossing appelle.
//
// Le NEX de base s'arrête à la méthode 8 pour Utility ; tout au-delà retombe sur
// « non implémenté », ce que le jeu traduit par une erreur de communication. La pile the previous stack
// que ce serveur remplace corrigeait précisément ces méthodes-là (Utility 9 et 10, Ranking
// GetEventMatchResult) — les oublier au portage aurait cassé ce qui fonctionnait.
//
// On SUPERPOSE au handler du cœur plutôt que de le remplacer : le cœur continue de répondre
// aux méthodes standard (réglages, identifiant unique NEX). Les remplacer entièrement a déjà
// coûté cher sur Splatoon 2, où cela masquait AcquireNexUniqueIDWithPassword — appelée
// uniquement sur un compte NEUF, si bien que seuls les nouveaux joueurs étaient touchés.

import (
	"fmt"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	// Utility 0x6E.9 AcquireTagId(list<Uint64>) -> Uint64 pTagId. Partage en session.
	methodUtilityAcquireTagID uint32 = 9
	// Utility 0x6E.10 UpdateCurrentUser(param) -> VOID.
	methodUtilityUpdateCurrentUser uint32 = 10
	// Ranking 0x70.25 GetEventMatchResult -> liste.
	methodRankingGetEventMatchResult uint32 = 25
)

// setupUtility superpose les méthodes Utility supplémentaires d'ACNH à celles du cœur.
func setupUtility(endpoint *nex.Endpoint) {
	base := nex.UtilityHandler()
	endpoint.Register(nex.ProtocolUtility, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		s := conn.Settings
		switch req.Method {
		case methodUtilityUpdateCurrentUser:
			// Réponse succès au corps VIDE. C'est ce qu'une measured réelle du serveur de
			// Nintendo a montré sur Splatoon 2 (0 octet), contre une analyse statique qui
			// concluait à une structure d'une trentaine d'octets. La mesure a tranché ;
			// ne pas « corriger » ceci sur la foi d'un désassemblage.
			fmt.Printf("[ACNH Utility] UpdateCurrentUser pid=%d callID=%d reqLen=%d -> succès vide\n",
				conn.PID, req.CallID, len(req.Body))
			return nex.NewRMCSuccess(s, nex.ProtocolUtility, req.Method, req.CallID, nil)

		case methodUtilityAcquireTagID:
			// Un identifiant non nul dérivé du PID appelant suffit.
			tagID := conn.PID
			if tagID == 0 {
				tagID = 1
			}
			out := nex.NewStreamOut(s)
			out.U64(tagID)
			fmt.Printf("[ACNH Utility] AcquireTagId -> pTagId=%d\n", tagID)
			return nex.NewRMCSuccess(s, nex.ProtocolUtility, req.Method, req.CallID, out.Bytes())

		default:
			// Tout le reste est du Utility standard : le cœur s'en charge et journalise
			// lui-même ce qu'il ne connaît pas, donc une méthode réellement nouvelle
			// resterait visible plutôt que d'être avalée ici.
			return base(conn, req)
		}
	})
	fmt.Println("[ACNH Utility] enregistré : UpdateCurrentUser(10), AcquireTagId(9) + Utility du cœur")
}

// setupRanking superpose GetEventMatchResult au Ranking du cœur.
func setupRanking(endpoint *nex.Endpoint) {
	base := nex.RankingHandler()
	endpoint.Register(nex.ProtocolRanking, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		if req.Method == methodRankingGetEventMatchResult {
			s := conn.Settings
			out := nex.NewStreamOut(s)
			out.U32(0) // liste vide
			fmt.Printf("[ACNH Ranking] GetEventMatchResult -> liste vide\n")
			return nex.NewRMCSuccess(s, nex.ProtocolRanking, req.Method, req.CallID, out.Bytes())
		}
		return base(conn, req)
	})
	fmt.Println("[ACNH Ranking] enregistré : GetEventMatchResult(25) + Ranking du cœur")
}
