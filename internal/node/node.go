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
	"github.com/codewiresh/codewire/internal/store"
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
	mgr.SetNameChangeHook(node.syncRelayGroupMemberships)
	mgr.SetSessionExitHook(node.cleanupRelayGroupMemberships)
	node.bundleCache = networkauth.NewBundleCache(func(ctx context.Context) (*networkauth.VerifierBundle, error) {
		if node.config.RelayURL == nil || strings.TrimSpace(*node.config.RelayURL) == "" {
			return nil, fmt.Errorf("relay is not configured")
		}
		return networkauth.FetchVerifierBundleWithToken(ctx, http.DefaultClient, *node.config.RelayURL, node.relayNetworkID(), node.relayVerifierAuthToken())
	})
	return node, nil
}

// Run starts the node. It writes a PID file, listens on a Unix socket,
// and optionally starts a WebSocket server. It blocks until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	// Write PID file.
	pid := os.Getpid()
	if err := os.WriteFile(n.pidPath, []byte(fmt.Sprintf("%d", pid)), 0o600); err != nil {
		return fmt.Errorf("writing pid file: %w", err)
	}

	// Remove stale socket if it exists.
	_ = os.Remove(n.socketPath)

	ln, err := net.Listen("unix", n.socketPath)
	if err != nil {
		// Fall back to /tmp if home dir doesn't support unix sockets (e.g. 9PFS).
		tmpSocket := "/tmp/codewire/codewire.sock"
		os.MkdirAll(filepath.Dir(tmpSocket), 0o700)
		_ = os.Remove(tmpSocket)
		ln, err = net.Listen("unix", tmpSocket)
		if err != nil {
			return fmt.Errorf("listening on unix socket: %w", err)
		}
		n.socketPath = tmpSocket
		// Symlink so clients find it at the expected path.
		_ = os.Symlink(tmpSocket, filepath.Join(n.dataDir, "codewire.sock"))
	}
	if err := os.Chmod(n.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("hardening unix socket permissions: %w", err)
	}
	slog.Info("listening on unix socket", "path", n.socketPath)

	defer n.Cleanup()

	// Start WebSocket server if configured (direct mode).
	peerServer := &peer.Server{
		Sessions:                n.Manager,
		NodeName:                n.config.Node.Name,
		AuthorizePeer:           n.authorizePeerRuntime,
		AuthorizeSender:         n.authorizePeerSender,
		AuthorizeDelivery:       n.authorizePeerDelivery,
		AuthorizeObserver:       n.authorizePeerObserver,
		RequireRemoteSenderAuth: true,
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
			n.authorizeLocalDelivery,
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

func (n *Node) relayVerifierAuthToken() string {
	if n != nil && n.config != nil && n.config.RelayToken != nil {
		if token := strings.TrimSpace(*n.config.RelayToken); token != "" {
			return token
		}
	}
	return resolveUserRelayAuthToken()
}

func (n *Node) relayNodeToken() string {
	if n == nil || n.config == nil || n.config.RelayToken == nil {
		return ""
	}
	return strings.TrimSpace(*n.config.RelayToken)
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
		handleClient(reader, writer, n.Manager, n.KVStore, n.authorizeLocalDelivery, n.issueSenderDelegation)
	})
	mux.HandleFunc("/peer", func(w http.ResponseWriter, r *http.Request) {
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
		slog.Warn("tailnet peer server skipped: missing config",
			"nil_node", n == nil,
			"nil_config", n != nil && n.config == nil,
			"nil_relay_url", n != nil && n.config != nil && n.config.RelayURL == nil,
			"nil_relay_token", n != nil && n.config != nil && n.config.RelayToken == nil)
		return
	}

	slog.Info("tailnet peer server starting", "relay", *n.config.RelayURL)

	issued, err := networkauth.IssueNodeRuntimeCredential(ctx, http.DefaultClient, *n.config.RelayURL, *n.config.RelayToken)
	if err != nil {
		slog.Error("tailnet runtime credential failed", "err", err)
		return
	}
	slog.Info("tailnet runtime credential issued")

	conn, err := peer.StartNodeTailnetListener(ctx, *n.config.RelayURL, issued.Credential, peerServer)
	if err != nil {
		slog.Error("tailnet peer listener failed", "err", err)
		return
	}
	slog.Info("tailnet peer listener started")
	defer conn.Close()

	<-ctx.Done()
}

func (n *Node) authorizePeerRuntime(ctx context.Context, token string) (*peer.AuthenticatedPeer, error) {
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("node config is unavailable")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("runtime credential is required")
	}
	if n.bundleCache == nil {
		return nil, fmt.Errorf("verifier bundle is unavailable")
	}
	if n.runtimeSeen == nil {
		return nil, fmt.Errorf("runtime replay cache is unavailable")
	}
	bundle, err := n.bundleCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading verifier bundle: %w", err)
	}
	claims, err := networkauth.VerifyRuntimeCredential(token, bundle, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if claims.NetworkID != n.relayNetworkID() {
		return nil, fmt.Errorf("runtime credential network mismatch")
	}
	if err := n.runtimeSeen.ConsumeRuntime(claims, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &peer.AuthenticatedPeer{
		NetworkID:   claims.NetworkID,
		SubjectKind: claims.SubjectKind,
		SubjectID:   claims.SubjectID,
	}, nil
}

func (n *Node) relayNetworkID() string {
	if n == nil || n.config == nil || n.config.RelayNetwork == nil {
		return ""
	}
	return networkauth.ResolveNetworkID(*n.config.RelayNetwork)
}

func (n *Node) syncRelayGroupMemberships(_ uint32, oldName, newName string, tags []string) error {
	groups := groupNamesFromTags(tags)
	if len(groups) == 0 {
		return nil
	}
	if n == nil || n.config == nil || n.config.RelayURL == nil || strings.TrimSpace(*n.config.RelayURL) == "" {
		return fmt.Errorf("relay is not configured")
	}
	if n.relayNodeToken() == "" {
		return fmt.Errorf("relay node token is unavailable")
	}
	nodeName := strings.TrimSpace(n.config.Node.Name)
	if nodeName == "" {
		return fmt.Errorf("node name is unavailable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	newName = strings.TrimSpace(newName)
	oldName = strings.TrimSpace(oldName)
	for _, groupName := range groups {
		if newName != "" {
			if err := networkauth.AddNodeGroupMember(ctx, http.DefaultClient, *n.config.RelayURL, n.relayNodeToken(), groupName, nodeName, newName); err != nil {
				return fmt.Errorf("syncing group %q for %s:%s: %w", groupName, nodeName, newName, err)
			}
		}
	}
	for _, groupName := range groups {
		if oldName != "" && oldName != newName {
			if err := networkauth.RemoveNodeGroupMember(ctx, http.DefaultClient, *n.config.RelayURL, n.relayNodeToken(), groupName, nodeName, oldName); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
				return fmt.Errorf("removing old group member %q for %s:%s: %w", groupName, nodeName, oldName, err)
			}
		}
	}
	return nil
}

func (n *Node) cleanupRelayGroupMemberships(_ uint32, name string, tags []string) {
	groups := groupNamesFromTags(tags)
	if len(groups) == 0 {
		return
	}
	if n == nil || n.config == nil || n.config.RelayURL == nil || strings.TrimSpace(*n.config.RelayURL) == "" || n.relayNodeToken() == "" {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	nodeName := strings.TrimSpace(n.config.Node.Name)
	if nodeName == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, groupName := range groups {
		if err := networkauth.RemoveNodeGroupMember(ctx, http.DefaultClient, *n.config.RelayURL, n.relayNodeToken(), groupName, nodeName, name); err != nil && !strings.Contains(err.Error(), "HTTP 404") {
			slog.Warn("failed to clean up relay group membership", "group", groupName, "node", nodeName, "session", name, "err", err)
		}
	}
}

func groupNamesFromTags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tags))
	groups := make([]string, 0, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if !strings.HasPrefix(tag, "group:") {
			continue
		}
		groupName := strings.TrimSpace(strings.TrimPrefix(tag, "group:"))
		if groupName == "" {
			continue
		}
		if _, ok := seen[groupName]; ok {
			continue
		}
		seen[groupName] = struct{}{}
		groups = append(groups, groupName)
	}
	return groups
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
		DisplayName:  label,
		SessionID:    claims.FromSessionID,
		SessionName:  claims.FromSessionName,
		SourceGroups: append([]string(nil), claims.SourceGroups...),
	}, nil
}

func (n *Node) authorizePeerDelivery(ctx context.Context, sender *peer.AuthorizedSender, to *peer.SessionLocator, verb string) error {
	if sender == nil || to == nil {
		return nil
	}
	targetName, err := n.resolveTargetSessionName(to)
	if err != nil {
		return err
	}
	if targetName == "" {
		return nil
	}
	bindings, err := n.fetchGroupBindings(ctx, targetName)
	if err != nil {
		return err
	}
	return enforceGroupBindings(bindings, sender.SourceGroups, verb)
}

func (n *Node) authorizeLocalDelivery(ctx context.Context, fromID, toID uint32, verb string) error {
	targetName := strings.TrimSpace(n.Manager.GetName(toID))
	if targetName == "" {
		return nil
	}
	bindings, err := n.fetchGroupBindings(ctx, targetName)
	if err != nil {
		return err
	}
	var sourceGroups []string
	if fromID != 0 {
		sourceGroups = n.Manager.GroupNames(fromID)
	}
	return enforceGroupBindings(bindings, sourceGroups, verb)
}

func (n *Node) authorizePeerObserver(ctx context.Context, principal *peer.AuthenticatedPeer, verb string, session *peer.SessionLocator, observerCap string) error {
	if principal == nil {
		return fmt.Errorf("peer principal is unavailable")
	}
	if session == nil {
		return fmt.Errorf("missing session locator")
	}
	if strings.TrimSpace(observerCap) == "" {
		return fmt.Errorf("missing observer grant")
	}
	bundle, err := n.bundleCache.Get(ctx)
	if err != nil {
		return fmt.Errorf("loading verifier bundle: %w", err)
	}
	claims, err := networkauth.VerifyObserverDelegation(observerCap, bundle, time.Now().UTC())
	if err != nil {
		return err
	}
	if claims.NetworkID != n.relayNetworkID() {
		return fmt.Errorf("observer grant network mismatch")
	}
	if claims.TargetNode != n.config.Node.Name {
		return fmt.Errorf("observer grant target node mismatch")
	}
	if claims.AudienceSubjectKind != principal.SubjectKind || claims.AudienceSubjectID != principal.SubjectID {
		return fmt.Errorf("observer grant audience mismatch")
	}
	if !delegationAllowsVerb(claims.Verbs, verb) {
		return fmt.Errorf("observer grant does not allow %s", verb)
	}
	if err := n.matchObserverSession(session, claims); err != nil {
		return err
	}
	return nil
}

func (n *Node) matchObserverSession(locator *peer.SessionLocator, claims *networkauth.ObserverDelegationClaims) error {
	if locator == nil {
		return fmt.Errorf("missing session locator")
	}
	if locator.ID != nil {
		if claims.SessionID != nil && *claims.SessionID != *locator.ID {
			return fmt.Errorf("observer grant session id mismatch")
		}
		if claims.SessionName != "" && n.Manager.GetName(*locator.ID) != claims.SessionName {
			return fmt.Errorf("observer grant session name mismatch")
		}
		return nil
	}
	if strings.TrimSpace(locator.Name) == "" {
		return fmt.Errorf("missing session locator")
	}
	sessionName := strings.TrimSpace(locator.Name)
	if claims.SessionName != "" && claims.SessionName != sessionName {
		return fmt.Errorf("observer grant session name mismatch")
	}
	if claims.SessionID != nil {
		resolved, err := n.Manager.ResolveByName(strings.TrimPrefix(sessionName, "@"))
		if err != nil {
			return fmt.Errorf("observer grant session id mismatch")
		}
		if resolved != *claims.SessionID {
			return fmt.Errorf("observer grant session id mismatch")
		}
	}
	return nil
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

func (n *Node) resolveTargetSessionName(locator *peer.SessionLocator) (string, error) {
	if locator == nil {
		return "", fmt.Errorf("missing target session")
	}
	if locator.ID != nil {
		return strings.TrimSpace(n.Manager.GetName(*locator.ID)), nil
	}
	return strings.TrimSpace(strings.TrimPrefix(locator.Name, "@")), nil
}

func (n *Node) fetchGroupBindings(ctx context.Context, sessionName string) ([]store.GroupBinding, error) {
	if n == nil || n.config == nil {
		return nil, fmt.Errorf("node config is unavailable")
	}
	if strings.TrimSpace(sessionName) == "" {
		return nil, nil
	}
	if n.config.RelayURL == nil || strings.TrimSpace(*n.config.RelayURL) == "" {
		return n.localGroupBindings(sessionName), nil
	}
	if n.config.RelayToken == nil || strings.TrimSpace(*n.config.RelayToken) == "" {
		return n.localGroupBindings(sessionName), nil
	}
	bindings, err := networkauth.FetchNodeGroupBindings(ctx, http.DefaultClient, *n.config.RelayURL, *n.config.RelayToken, n.config.Node.Name, sessionName)
	if err != nil {
		return n.localGroupBindings(sessionName), nil
	}
	if len(bindings) == 0 {
		return n.localGroupBindings(sessionName), nil
	}
	return bindings, nil
}

func enforceGroupBindings(bindings []store.GroupBinding, sourceGroups []string, verb string) error {
	if len(bindings) == 0 {
		return nil
	}
	allowedByOpenPolicy := false
	for _, binding := range bindings {
		if binding.MessagesPolicy == store.GroupMessagesOpen {
			allowedByOpenPolicy = true
			break
		}
	}
	if allowedByOpenPolicy {
		return nil
	}

	sourceSet := make(map[string]struct{}, len(sourceGroups))
	for _, groupName := range sourceGroups {
		groupName = strings.TrimSpace(groupName)
		if groupName == "" {
			continue
		}
		sourceSet[groupName] = struct{}{}
	}
	for _, binding := range bindings {
		if _, ok := sourceSet[strings.TrimSpace(binding.GroupName)]; ok {
			return nil
		}
	}
	return fmt.Errorf("group policy forbids %s delivery to this session", verb)
}

func (n *Node) localGroupBindings(sessionName string) []store.GroupBinding {
	sessionName = strings.TrimSpace(strings.TrimPrefix(sessionName, "@"))
	if sessionName == "" || n == nil || n.Manager == nil {
		return nil
	}
	sessionID, err := n.Manager.ResolveByName(sessionName)
	if err != nil {
		return nil
	}
	groups := n.Manager.GroupNames(sessionID)
	if len(groups) == 0 {
		return nil
	}
	bindings := make([]store.GroupBinding, 0, len(groups))
	for _, groupName := range groups {
		bindings = append(bindings, store.GroupBinding{
			GroupName:      groupName,
			MessagesPolicy: store.GroupMessagesInternalOnly,
			DebugPolicy:    store.GroupDebugObserveOnly,
		})
	}
	return bindings
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
