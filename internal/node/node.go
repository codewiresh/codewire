package node

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/codewiresh/codewire/internal/auth"
	"github.com/codewiresh/codewire/internal/config"
	"github.com/codewiresh/codewire/internal/connection"
	"github.com/codewiresh/codewire/internal/networkauth"
	"github.com/codewiresh/codewire/internal/peer"
	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/relay"
	"github.com/codewiresh/codewire/internal/session"
)

// Node manages PTY sessions, accepting connections over a Unix domain socket
// and optionally a WebSocket listener.
type Node struct {
	Manager     *session.SessionManager
	KVStore     *session.KVStore
	socketPath  string
	pidPath     string
	config      *config.Config
	dataDir     string
	bundleCache *networkauth.BundleCache
	runtimeSeen *networkauth.ReplayCache
	senderSeen  *networkauth.ReplayCache
}

// NewNode creates a Node rooted at dataDir. It loads the configuration,
// initialises the session manager, and ensures an auth token exists on disk.
func NewNode(dataDir string) (*Node, error) {
	cfg, err := config.LoadConfig(dataDir)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	mgr, err := session.NewSessionManager(dataDir)
	if err != nil {
		return nil, fmt.Errorf("creating session manager: %w", err)
	}

	token, err := auth.LoadOrGenerateToken(dataDir)
	if err != nil {
		return nil, fmt.Errorf("loading auth token: %w", err)
	}
	slog.Info("auth token ready", "token", token)

	node := &Node{
		Manager:     mgr,
		KVStore:     session.NewKVStore(),
		socketPath:  filepath.Join(dataDir, "codewire.sock"),
		pidPath:     filepath.Join(dataDir, "codewire.pid"),
		config:      cfg,
		dataDir:     dataDir,
		runtimeSeen: networkauth.NewReplayCache(),
		senderSeen:  networkauth.NewReplayCache(),
	}
	node.bundleCache = networkauth.NewBundleCache(func(ctx context.Context) (*networkauth.VerifierBundle, error) {
		if node.config.RelayURL == nil || strings.TrimSpace(*node.config.RelayURL) == "" {
			return nil, fmt.Errorf("relay is not configured")
		}
		return networkauth.FetchVerifierBundle(ctx, http.DefaultClient, *node.config.RelayURL, node.relayNetworkID())
	})
	return node, nil
}

// Run starts the node. It writes a PID file, listens on a Unix socket,
// and optionally starts a WebSocket server. It blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	// Write PID file.
	pid := os.Getpid()
	if err := os.WriteFile(n.pidPath, []byte(fmt.Sprintf("%d", pid)), 0o644); err != nil {
		return fmt.Errorf("writing pid file: %w", err)
	}

	// Remove stale socket if it exists.
	_ = os.Remove(n.socketPath)

	ln, err := net.Listen("unix", n.socketPath)
	if err != nil {
		return fmt.Errorf("listening on unix socket: %w", err)
	}
	slog.Info("listening on unix socket", "path", n.socketPath)

	defer n.Cleanup()

	// Start WebSocket server if configured (direct mode).
	peerServer := &peer.Server{
		Sessions:        n.Manager,
		NodeName:        n.config.Node.Name,
		AuthorizeSender: n.authorizePeerSender,
	}

	if n.config.Node.Listen != nil {
		addr := *n.config.Node.Listen
		go func() {
			if wsErr := n.runWSServer(ctx, addr, peerServer); wsErr != nil {
				slog.Error("websocket server error", "err", wsErr)
			}
		}()
	}

	// Start relay agent if relay URL and token are configured.
	if n.config.RelayURL != nil {
		if (n.config.RelayToken == nil || *n.config.RelayToken == "") && n.config.RelayInviteToken != nil && *n.config.RelayInviteToken != "" {
			nodeToken, err := relay.RegisterWithInvite(ctx, *n.config.RelayURL, n.config.Node.Name, *n.config.RelayInviteToken)
			if err != nil {
				slog.Error("relay invite bootstrap failed", "err", err)
			} else {
				n.config.RelayToken = &nodeToken
				n.config.RelayInviteToken = nil
				if err := config.SaveConfig(n.dataDir, n.config); err != nil {
					slog.Error("saving relay bootstrap config failed", "err", err)
				}
			}
		}
		if (n.config.RelayToken == nil || *n.config.RelayToken == "") && n.config.RelayNetwork != nil && strings.TrimSpace(*n.config.RelayNetwork) != "" {
			if userToken := resolveUserRelayAuthToken(); userToken != "" {
				nodeToken, err := relay.RegisterWithAuthToken(ctx, *n.config.RelayURL, *n.config.RelayNetwork, n.config.Node.Name, userToken)
				if err != nil {
					slog.Error("relay auto-enrollment failed", "err", err)
				} else {
					n.config.RelayToken = &nodeToken
					if err := config.SaveConfig(n.dataDir, n.config); err != nil {
						slog.Error("saving relay auto-enrollment config failed", "err", err)
					}
				}
			}
		}

		if n.config.RelayToken != nil && *n.config.RelayToken != "" {
			go relay.RunAgent(ctx, relay.AgentConfig{
				RelayURL:  *n.config.RelayURL,
				NodeName:  n.config.Node.Name,
				NodeToken: *n.config.RelayToken,
				PeerURL:   stringPtrValue(n.config.Node.ExternalURL),
			})
			go n.runTailnetPeerServer(ctx, peerServer)
		}
	}

	// Start periodic status refresh (every 5 seconds).
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n.Manager.RefreshStatuses()
			}
		}
	}()

	// Start persistence manager.
	go persistenceManager(n.Manager)

	// Close the listener when ctx is cancelled so Accept unblocks.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Accept loop.
	for {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			// Check if we were shut down.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			slog.Error("accept error", "err", acceptErr)
			continue
		}
		go handleClient(
			connection.NewUnixReader(conn),
			connection.NewUnixWriter(conn),
			n.Manager,
			n.KVStore,
			n.issueSenderDelegation,
		)
	}
}

func resolveUserRelayAuthToken() string {
	if token := strings.TrimSpace(os.Getenv("CODEWIRE_API_KEY")); token != "" {
		return token
	}
	cfg, err := platform.LoadConfig()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.SessionToken)
}

// Cleanup removes the Unix socket and PID files.
func (n *Node) Cleanup() {
	_ = os.Remove(n.socketPath)
	_ = os.Remove(n.pidPath)
}

// runWSServer starts an HTTP server that upgrades /ws connections to WebSocket
// and dispatches them through the standard client handler after validating the
// auth token.
func (n *Node) runWSServer(ctx context.Context, addr string, peerServer *peer.Server) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if !auth.ValidateToken(n.dataDir, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		wsConn, err := websocket.Accept(w, r, nil)
		if err != nil {
			slog.Error("websocket accept error", "err", err)
			return
		}

		wsCtx := r.Context()
		reader := connection.NewWSReader(wsCtx, wsConn)
		writer := connection.NewWSWriter(wsCtx, wsConn)
		handleClient(reader, writer, n.Manager, n.KVStore, n.issueSenderDelegation)
	})
	mux.HandleFunc("/peer", func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if !n.validatePeerToken(r.Context(), token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		wsConn, err := websocket.Accept(w, r, nil)
		if err != nil {
			slog.Error("peer websocket accept error", "err", err)
			return
		}
		peerServer.ServeWebSocket(r.Context(), wsConn)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	slog.Info("websocket server listening", "addr", addr)

	// Shut down gracefully when ctx is cancelled.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("websocket server: %w", err)
	}
	return nil
}

func (n *Node) runTailnetPeerServer(ctx context.Context, peerServer *peer.Server) {
	if n == nil || n.config == nil || n.config.RelayURL == nil || n.config.RelayToken == nil {
		return
	}

	issued, err := networkauth.IssueNodeRuntimeCredential(ctx, http.DefaultClient, *n.config.RelayURL, *n.config.RelayToken)
	if err != nil {
		slog.Error("tailnet runtime credential failed", "err", err)
		return
	}

	conn, err := peer.StartNodeTailnetListener(ctx, *n.config.RelayURL, issued.Credential, peerServer)
	if err != nil {
		slog.Error("tailnet peer listener failed", "err", err)
		return
	}
	defer conn.Close()

	<-ctx.Done()
}

func (n *Node) validatePeerToken(ctx context.Context, token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	return n.validateRuntimeCredential(ctx, token)
}

func (n *Node) validateRuntimeCredential(ctx context.Context, token string) bool {
	if n.bundleCache == nil {
		return false
	}
	bundle, err := n.bundleCache.Get(ctx)
	if err != nil {
		return false
	}
	claims, err := networkauth.VerifyRuntimeCredential(token, bundle, time.Now().UTC())
	if err != nil {
		return false
	}
	if claims.NetworkID != n.relayNetworkID() {
		return false
	}
	return n.runtimeSeen.ConsumeRuntime(claims, time.Now().UTC()) == nil
}

func (n *Node) relayNetworkID() string {
	if n == nil || n.config == nil || n.config.RelayNetwork == nil {
		return ""
	}
	return networkauth.ResolveNetworkID(*n.config.RelayNetwork)
}

func (n *Node) issueSenderDelegation(ctx context.Context, sessionID uint32, verb, audienceNode string) (*networkauth.SenderDelegationResponse, error) {
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("node config is unavailable")
	}
	if n.config.RelayURL == nil || strings.TrimSpace(*n.config.RelayURL) == "" {
		return nil, fmt.Errorf("relay is not configured")
	}
	if n.config.RelayToken == nil || strings.TrimSpace(*n.config.RelayToken) == "" {
		return nil, fmt.Errorf("relay node token is not configured")
	}
	sessionName := n.Manager.GetName(sessionID)
	return networkauth.IssueNodeSenderDelegation(
		ctx,
		http.DefaultClient,
		*n.config.RelayURL,
		*n.config.RelayToken,
		n.config.Node.Name,
		&sessionID,
		sessionName,
		[]string{strings.TrimSpace(verb)},
		strings.TrimSpace(audienceNode),
	)
}

func (n *Node) authorizePeerSender(ctx context.Context, verb string, from *peer.SessionLocator, senderCap string) (*peer.AuthorizedSender, error) {
	if from == nil {
		return nil, nil
	}
	if strings.TrimSpace(senderCap) == "" {
		return nil, fmt.Errorf("missing sender delegation")
	}
	if strings.TrimSpace(from.Node) == "" {
		return nil, fmt.Errorf("sender locator must include source node")
	}
	bundle, err := n.bundleCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading verifier bundle: %w", err)
	}
	claims, err := networkauth.VerifySenderDelegation(senderCap, bundle, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if claims.NetworkID != n.relayNetworkID() {
		return nil, fmt.Errorf("sender delegation network mismatch")
	}
	if claims.SourceNode != strings.TrimSpace(from.Node) {
		return nil, fmt.Errorf("sender delegation source node mismatch")
	}
	if claims.AudienceNode != "" && claims.AudienceNode != n.config.Node.Name {
		return nil, fmt.Errorf("sender delegation audience mismatch")
	}
	if !delegationAllowsVerb(claims.Verbs, verb) {
		return nil, fmt.Errorf("sender delegation does not allow %s", verb)
	}
	if from.ID != nil {
		if claims.FromSessionID == nil || *claims.FromSessionID != *from.ID {
			return nil, fmt.Errorf("sender delegation session id mismatch")
		}
	}
	if strings.TrimSpace(from.Name) != "" && claims.FromSessionName != strings.TrimSpace(from.Name) {
		return nil, fmt.Errorf("sender delegation session name mismatch")
	}

	label := claims.SourceNode
	switch {
	case claims.FromSessionName != "":
		label += ":" + claims.FromSessionName
	case claims.FromSessionID != nil:
		label += fmt.Sprintf(":%d", *claims.FromSessionID)
	default:
		return nil, fmt.Errorf("sender delegation missing session identity")
	}
	if err := n.senderSeen.ConsumeSender(claims, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &peer.AuthorizedSender{
		DisplayName: label,
		SessionID:   claims.FromSessionID,
		SessionName: claims.FromSessionName,
	}, nil
}

func delegationAllowsVerb(verbs []string, verb string) bool {
	verb = strings.TrimSpace(verb)
	for _, candidate := range verbs {
		if strings.TrimSpace(candidate) == verb {
			return true
		}
	}
	return false
}

// persistenceManager debounces persist signals from the session manager.
// After receiving a signal it waits 500ms for additional signals before
// flushing metadata to disk.
func persistenceManager(manager *session.SessionManager) {
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}

	pending := false

	for {
		select {
		case _, ok := <-manager.PersistCh:
			if !ok {
				// Channel closed — flush any pending write and exit.
				if pending {
					manager.PersistMeta()
				}
				return
			}
			// Reset the debounce timer. If it was already running, stop it first.
			if !timer.Stop() && pending {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(500 * time.Millisecond)
			pending = true

		case <-timer.C:
			if pending {
				manager.PersistMeta()
				pending = false
			}
		}
	}
}

func stringPtrValue(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}
