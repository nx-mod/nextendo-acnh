// Command acnh fait tourner les serveurs en ligne d'Animal Crossing: New Horizons
// (authentification + sécurisé) sur la pile NEX maison — notre propre implémentation
// fermée, sans aucun code  de the previous stack.
//
// Il remplace le couple the previous stack acnh-auth-local / acnh-secure-local. Ce portage a trois
// raisons, dans cet ordre d'importance :
//
//  1. Licence. the previous stack est sous -3.0 : la faire tourner comme service en réseau ouvre
//     à quiconque s'y connecte le droit d'en réclamer les sources. C'est exactement ce que
//     le cœur maison a été écrit pour éviter, et Animal Crossing était le dernier jeu resté
//     dessus.
//  2. Exploitation. Éviction des connexions mortes, kick administrateur, tableau de bord
//     fermé par défaut : tout cela vit dans le cœur et ne s'appliquait donc pas à ACNH.
//  3. Simplicité. La pile the previous stack faisait 3075 lignes réparties sur deux binaires et une
//     base PostgreSQL ; le cœur absorbe le protocole, il reste la logique du jeu.
//
// Deux serveurs NEX dans un seul processus :
//   - auth   (:443)    TicketGranting — LoginEx délivre le ticket Kerberos.
//   - secure (:60007)  SecureConnection + matchmaking + NAT-traversal, plus la recherche
//     par participant (visite d'ami) et par Dodo Code.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	// accessKey est la clé d'accès NEX d'Animal Crossing: New Horizons
	// (MK8 09c1c475, S2 4eb18d39, Smash 9587602b).
	accessKey      = "v43a10em"
	nexVersion     = 40000
	securePID      = 2
	securePassword = "securepasswordplz1"
	sessionKeyLen  = 32
	// sniHost est le nom d'hôte du serveur de jeu vers lequel ACNH est redirigé ; le proxy
	// TLS-passthrough route le :443 vers ce processus grâce à lui. (ACNH game server 2EE2E300.)
	sniHost = ""
	// acnhAppID identifie Animal Crossing: New Horizons auprès du service de comptes, pour
	// que les amis voient « en train de jouer à Animal Crossing ».
	acnhAppID = "01006f8002326000"
)

var (
	nextendoHost = envOr("NEXTENDO_HOST", sniHost)
	authPort     = envOrInt("AUTH_PORT", 443)
	securePort   = envOrInt("SECURE_PORT", 60007)
	certFile     = envOr("CERT_FILE", `cert.pem`)
	keyFile      = envOr("KEY_FILE", `key.pem`)

	// nextendoSecret signe les jetons de connexion NEX « nx2. » émis par le service de
	// comptes. Il DOIT être identique octet pour octet à celui de nextendo-account.
	nextendoSecret = loadNextendoSecret()
	// requireAccount, à "1", refuse toute connexion sans jeton Nextendo valide.
	requireAccount = os.Getenv("NEXTENDO_REQUIRE_ACCOUNT") == "1"
)

func main() {
	settings := nex.NewSwitchSettings(accessKey, nexVersion)

	// --- Serveur d'authentification (:443) ---
	// « prudps » (PRUDP *Secure*), pas « prudp » : le schéma de cette station est ce qui dit
	// au client que la cible est un serveur sécurisé et donc qu'il doit livrer son ticket
	// Kerberos dans le CONNECT. Avec « prudp » la poignée de main aboutit mais le CONNECT
	// arrive VIDE — ni ticket, ni clé de session — et le jeu meurt dès que Pia a besoin de
	// la session. Ce piège a coûté des jours sur Smash ; ne pas le rouvrir ici.
	secureURL := nex.NewStationURL("prudps")
	secureURL.Set("address", nextendoHost)
	secureURL.SetInt("port", securePort)
	secureURL.SetInt("CID", 1)
	secureURL.SetInt("PID", securePID)
	secureURL.SetInt("sid", 1)
	secureURL.SetInt("stream", 10)
	secureURL.SetInt("type", 2) // public

	authEndpoint := nex.NewEndpoint(settings)
	authCfg := &nex.AuthConfig{
		Settings:         settings,
		SecurePID:        securePID,
		SecurePassword:   securePassword,
		SecureStationURL: secureURL,
		ServerName:       "Nextendo",
		SessionKeyLength: sessionKeyLen,
		ResolveUser:      resolveUser,
	}
	authEndpoint.Register(nex.ProtocolTicketGranting, authCfg.Handler())
	authEndpoint.OnRMC = logRMC("Auth")
	authServer := nex.NewServer(authEndpoint)

	// --- Serveur sécurisé (:60007) ---
	// Version mineure PRUDP. La pile the previous stack que remplace ce serveur RENVOYAIT simplement au
	// client la valeur qu'il avait lui-même annoncée (prudp_endpoint.go : « we can just
	// support what the client wants »), alors que ce cœur en impose une. Pour cette
	// génération NEX 4.x, la valeur mesurée sur les autres titres Switch (Splatoon 2, Smash,
	// Mario Maker 2) est 0 — c'est donc celle qui reproduit ce qu'ACNH reçoit aujourd'hui.
	// Réglable : si la poignée de main se comporte mal au premier essai, c'est le premier
	// paramètre à remettre en cause.
	secureSettings := nex.NewSwitchSettings(accessKey, nexVersion)
	secureSettings.PrudpMinorVersion = envOrInt("NEXTENDO_PRUDP_MINOR", 0)
	secureEndpoint := nex.NewEndpoint(secureSettings)
	secureEndpoint.SetSecureAccount(securePassword, securePID)

	mm := nex.NewMatchmaking()
	// Visite d'île entre amis. ACNH localise l'ami choisi via FindMatchmakeSessionByParticipant
	// (0x6D.0x33) ; le cœur répond une liste vide par défaut, ce qui revient à annoncer
	// « ton ami n'a aucune île ouverte ». Seul ACNH active la vraie recherche : Smash appelle
	// la même méthode au démarrage et s'appuie sur la liste vide.
	mm.FindByParticipantEnabled = true
	// Le « Dodo Code » de l'hôte n'arrive QUE par la mise à jour partielle de session
	// (0x6D.0x2C). Sans écriture réelle, il n'est jamais enregistré et aucune recherche par
	// code ne peut aboutir. Splatoon 2 n'appelle cette méthode qu'en fin de partie coop,
	// où seul l'acquittement compte : d'où l'activation ici et pas ailleurs.
	mm.SessionPartPersists = true
	// GetSessionURLs doit rendre [station PUBLIQUE, station LAN] avec Pa=<adresse publique>,
	// exactement comme le serveur the previous stack contre lequel ACNH fonctionne. La Pia d'ACNH prend la
	// 1ʳᵉ station comme candidat P2P primaire et lit son Pa comme cible : la forme MK8 par défaut
	// ([lan, public], Pa=<privée>) envoie le visiteur sur l'IP LAN de l'hôte → cale sur « Getting
	// ready to depart » (2618-0502). Prouvé par diff measured the previous stack vs NEXtendo (visite d'île).
	mm.PublicStationFirst = true
	// Réponse au JOIN : annoncer le nombre de participants AVANT l'ajout du visiteur (comme the previous stack),
	// sinon la Pia d'ACNH attend une « autre console » de trop et échoue (2618-0502). Cf. le diff
	// de measured : the previous stack Join/39 renvoie NumParticipants=1 (l'hôte seul) là où le cœur renvoyait 2.
	mm.JoinRespExistingCount = true
	// Liste des amis joignables (menu de visite) : les données de notification publiées par
	// les amis ayant ouvert leur porte. La source est le graphe d'amitié de nextendo-account.
	mm.FriendPIDs = acnhFriendPIDs

	// ACNH tourne sur une Pia 5.x moderne : sa station PUBLIQUE doit être type=0x0B
	// (BehindNAT|Public|Switch) + Pa, PAS la forme Wii-U-era type=0x03 de Splatoon 2. Prouvé
	// par diff measured : le serveur the previous stack contre lequel ACNH fonctionne renvoie type=11 dans
	// l'InitiateProbe NAT ; avec LegacyPiaConfig (type=3) la Pia d'ACNH ne reconnaît pas la
	// station publique du pair, le perçage ne se construit pas et la visite cale sur « Getting
	// ready to depart » (2618-0502) alors même que le hole-punch serveur réussit.
	secureEndpoint.Register(nex.ProtocolSecureConnection, nex.SecureConnectionHandlerWithConfig(nex.SwitchPia519Config()))
	secureEndpoint.Register(nex.ProtocolMatchmakeExtension, mm.ExtensionHandler())
	secureEndpoint.Register(nex.ProtocolMatchMaking, mm.MatchMakingHandler())
	secureEndpoint.Register(nex.ProtocolMatchMakingExt, mm.MatchMakingExtHandler())
	secureEndpoint.Register(nex.ProtocolNATTraversal, nex.NATTraversalHandler())
	// Utility et Ranking sont SUPERPOSÉS : ACNH appelle des méthodes que le NEX standard
	// ne définit pas (Utility 9 et 10, Ranking 25), et la pile the previous stack les corrigeait déjà.
	setupUtility(secureEndpoint)
	setupRanking(secureEndpoint)
	setupDataStoreDiscovery(secureEndpoint)

	logSecure := logRMC("Secure")
	secureEndpoint.OnRMC = func(c *nex.Connection, req *nex.RMCMessage) {
		logSecure(c, req)
		noteRMC(c, req)         // alimente le tableau de bord
		notePresenceSeen(c.PID) // tout paquet d'un PID = ce compte joue à ACNH maintenant
	}
	secureEndpoint.OnConnect = func(c *nex.Connection) {
		fmt.Printf("[ACNH Secure] connecté pid=%d id=%d addr=%s\n", c.PID, c.ID, c.RemoteAddr)
	}
	// Libère l'île du joueur quand sa connexion meurt. Sans cela un rassemblement n'est retiré
	// que si le client appelle poliment UnregisterGathering : un joueur qui plante laisse son
	// île ouverte pour toujours, visible et injoignable.
	secureEndpoint.OnDisconnect = func(c *nex.Connection) {
		mm.RemovePlayer(c.PID)
	}
	secureServer := nex.NewServer(secureEndpoint)

	// Éviction automatique des connexions mortes + kick administrateur via le tableau de
	// bord. C'est l'un des apports du portage : la pile the previous stack n'avait ni l'un ni l'autre,
	// et une session perdue y restait enregistrée indéfiniment.
	secureEndpoint.StartReaper()
	go startDashboard(secureEndpoint, mm)
	startPresenceReporter()

	// Quand l'authentification est derrière un proxy TLS-passthrough (a reverse-proxy sur le :443
	// partagé), activer le protocole PROXY pour qu'elle voie la VRAIE IP de la console.
	proxyProto := os.Getenv("NEXTENDO_PROXY_PROTOCOL") == "1"
	go func() {
		fmt.Printf("[ACNH Auth] écoute WSS :%d (proxyProto=%v, station sécurisée -> %s)\n", authPort, proxyProto, secureURL.String())
		var err error
		if proxyProto {
			err = authServer.ListenSecureProxy(authPort, certFile, keyFile)
		} else {
			err = authServer.ListenSecure(authPort, certFile, keyFile)
		}
		if err != nil {
			fmt.Printf("[ACNH Auth] arrêté : %v\n", err)
		}
	}()

	fmt.Printf("[ACNH Secure] écoute WSS :%d\n", securePort)
	if err := secureServer.ListenSecure(securePort, certFile, keyFile); err != nil {
		fmt.Printf("[ACNH Secure] arrêté : %v\n", err)
	}
}

// setupDataStoreDiscovery répond au DataStore (0x73).
//
// L'usage qu'ACNH fait de ce protocole n'est PAS cartographié, contrairement à Splatoon 2
// dont les réponses sont rejouées depuis une measured réelle. On journalise donc chaque appel
// (méthode, taille des paramètres) et on répond succès vide : le jeu continue d'avancer et
// révèle exactement ce qu'il demande. C'est le comportement que la pile the previous stack avait déjà ;
// le remplacer par NotImplemented couperait ce qui marche aujourd'hui.
func setupDataStoreDiscovery(endpoint *nex.Endpoint) {
	const protocolDataStore uint16 = 0x73
	endpoint.Register(protocolDataStore, func(conn *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		fmt.Printf("[ACNH DataStore] pid=%d 0x73.%d callID=%d params=%d octets -> succès vide\n",
			conn.PID, req.Method, req.CallID, len(req.Body))
		return nex.NewRMCSuccess(conn.Settings, protocolDataStore, req.Method, req.CallID, nil)
	})
	fmt.Println("[ACNH DataStore] observation active sur DataStore(0x73) — journalise tout, répond succès vide")
}

// resolveUser associe un nom d'utilisateur LoginEx à un compte. Un jeton « nx2. » valide
// donne le PID persistant du compte ; sinon on dérive un PID anonyme stable.
func resolveUser(username string, extraData []byte) (uint64, []byte, bool) {
	// La clé source chiffre le ticket client et lui est rendue via pSourceKey, pour qu'il
	// puisse le déchiffrer. Elle DOIT faire 32 octets (taille de clé Kerberos Switch).
	sk := sha256.Sum256([]byte("nextendo-src:" + username))
	sourceKey := sk[:]

	// 1. Jeton nx2 signé → PID PERSISTANT du compte (+ gardes online).
	if pid, ok := nextendoPIDFromToken(username); ok {
		if allow, reason := nextendoOnlineCheck(pid, "ryujinx"); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 2. Nom numérique. Le bouton « Connexion Nextendo » de l'émulateur envoie le PID du
	// compte ; une vraie Switch CFW envoie son baasUserID (un grand identifiant NSA), qu'on
	// résout vers le PID du compte.
	if n, err := strconv.ParseUint(username, 10, 64); err == nil && n >= 1800000000 {
		// Le jeu envoie un PID NU comme identité (aucune signature). Les PID étant
		// séquentiels depuis 1800000001, envoyer le numéro d'un autre membre suffirait à
		// jouer sous son identité — et, via la garde « un seul endroit », à l'empêcher
		// lui-même de jouer. On referme la faille en EXIGEANT la preuve cryptographique
		// que l'émulateur (>= 1.7.1) glisse dans l'extraData du login : le jeton nx2 signé
		// (HMAC au secret serveur) porté par le claim "nnex" du id_token BAAS. On valide ce
		// jeton et on exige qu'il prouve EXACTEMENT le PID annoncé.
		provenPID, proven := uint64(0), false
		if tok, ok := nex.NexTokenFromLoginExtraData(extraData); ok {
			provenPID, proven = nextendoPIDFromToken(tok)
		}
		// L'enforce ne cible que la plage émulateur (username = le PID du compte lui-même).
		// Une vraie Switch (NSA >= 1810000000) n'envoie pas de jeton nx2 ; elle reste sur
		// resolveNSAtoPID pour ne pas casser les consoles CFW légitimes.
		if n < 1810000000 {
			switch {
			case proven && provenPID == n:
				fmt.Printf("[Auth][bind] pid=%d OK : le nx2 prouve le PID\n", n)
			case proven && provenPID != n:
				fmt.Printf("[Auth][bind] pid=%d USURPATION : le nx2 prouve %d, pas %d\n", n, provenPID, n)
			default:
				fmt.Printf("[Auth][bind] pid=%d SANS PREUVE : aucun nx2 dans l'extraData (build < 1.7.1 ?)\n", n)
			}
			if requireSignedToken() && !(proven && provenPID == n) {
				fmt.Printf("[Auth] pid=%d REFUSÉ : identité non prouvée (jeton nx2 signé requis)\n", n)
				return 0, nil, false
			}
		}
		pid, kind := n, "ryujinx"
		if n >= 1810000000 { // vraie Switch : NSA id -> PID de compte (online = comptes Nextendo UNIQUEMENT)
			kind = "switch"
			rp, st := resolveNSAtoPID(n)
			switch st {
			case nsaOK:
				pid = rp
				fmt.Printf("[Auth] NSA %d -> compte pid=%d\n", n, pid)
			case nsaUnknown:
				fmt.Printf("[Auth] NSA %d REFUSÉ (aucun compte Nextendo)\n", n)
				return 0, nil, false
			case nsaUnreachable:
				fmt.Printf("[Auth] NSA %d REFUSÉ (serveur de comptes injoignable)\n", n)
				return 0, nil, false
			}
		}
		// GARDES online : #6 e-mail vérifié + #5 un seul endroit + compte inconnu/désactivé.
		if allow, reason := nextendoOnlineCheck(pid, kind); !allow {
			fmt.Printf("[Auth] pid=%d online REFUSÉ (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 3. Anonyme / sans identité Nextendo.
	if requireAccount {
		fmt.Printf("[Auth] connexion anonyme REFUSÉE (compte Nextendo requis) : %q\n", username)
		return 0, nil, false
	}
	return anonymousPID(username), sourceKey, true
}

// revokedNexPayloads lists leaked nex_token payloads (pid.username.expiry) that must be
// rejected even though their HMAC is valid, without rotating the shared secret. Populated
// per deployment.
var revokedNexPayloads = map[string]bool{

}
// nextendoPIDFromToken valide un jeton « nx2.<b64(pid.username.expiry)>.<b64(hmac)> »
// signé par le service de comptes (HMAC-SHA256, préfixe « nex: »).
func nextendoPIDFromToken(s string) (uint64, bool) {
	if len(nextendoSecret) == 0 || !strings.HasPrefix(s, "nx2.") {
		return 0, false
	}
	parts := strings.Split(s[len("nx2."):], ".")
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + string(raw)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	if revokedNexPayloads[string(raw)] { // jeton revoque : refuse malgre une signature valide
		return 0, false
	}
	f := strings.SplitN(string(raw), ".", 3) // pid.username.expiry
	if len(f) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

// loadNextendoSecret charge le secret de signature des jetons NEX EXACTEMENT comme le fait
// nextendo-account : la variable NEXTENDO_SECRET telle quelle si elle est posée, sinon le
// fichier de clé partagé décodé depuis l'hexadécimal. Le service déployé n'a pas la variable
// et décode donc le fichier — il faut faire pareil ou l'empreinte ne correspondra pas.
func loadNextendoSecret() []byte {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		return []byte(v)
	}
	path := envOr("NEXTENDO_SECRET_FILE", "nextendo_secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if dec, derr := hex.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) >= 16 {
			return dec
		}
	}
	return nil
}

// anonymousPID dérive un PID stable dans la plage NEX à partir d'un nom d'utilisateur.
func anonymousPID(username string) uint64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(username))
	return 1800000000 + uint64(h.Sum32()%100000000)
}

func logRMC(tag string) func(*nex.Connection, *nex.RMCMessage) {
	return func(c *nex.Connection, req *nex.RMCMessage) {
		fmt.Printf("[ACNH %s] pid=%d proto=%#x method=%d call=%d\n", tag, c.PID, req.Protocol, req.Method, req.CallID)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// requireSignedToken : quand true, seule une identite prouvee par un jeton nx2 SIGNE est
// acceptee au LoginEx ; un PID nu est refuse. Desactive par defaut car l emulateur
// actuellement distribue envoie encore le PID nu — a activer apres la prochaine release.
func requireSignedToken() bool {
	v := os.Getenv("NEXTENDO_REQUIRE_SIGNED_TOKEN")
	return v == "1" || v == "true"
}
