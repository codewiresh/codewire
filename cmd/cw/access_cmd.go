package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
	"github.com/codewiresh/codewire/internal/store"
)

func accessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "access",
		Short: "Grant and manage remote session access",
	}

	cmd.AddCommand(
		accessAcceptCmd(),
		accessDropCmd(),
		accessGrantCmd(),
		accessInspectCmd(),
		accessListCmd(),
		accessPruneCmd(),
		accessRevokeCmd(),
		accessWatchCmd(),
	)
	return cmd
}

func accessAcceptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accept <token>",
		Short: "Accept and cache a remote access grant locally",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			accepted, err := client.AcceptAccessGrant(dataDir(), args[0])
			if err != nil {
				return err
			}
			target := formatAccessTarget(accepted.TargetNode, accepted.SessionID, accepted.SessionName)
			fmt.Fprintf(os.Stdout, "Accepted access grant for %s.\n", target)
			fmt.Fprintf(os.Stdout, "Grant ID: %s\n", accepted.GrantID)
			fmt.Fprintf(os.Stdout, "Expires: %s\n", accepted.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}
	return cmd
}

func accessGrantCmd() *cobra.Command {
	var (
		audience    string
		ttl         string
		allowRead   bool
		allowListen bool
		output      string
		networkID   string
		relayURL    string
		authToken   string
	)

	cmd := &cobra.Command{
		Use:   "grant <node>:<session>",
		Short: "Grant remote read/listen access to one session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			loc, err := parseSessionLocator(args[0])
			if err != nil {
				return err
			}
			if !loc.isRemote() {
				return fmt.Errorf("target must be <node>:<session>")
			}
			if strings.TrimSpace(audience) == "" {
				return fmt.Errorf("--to is required")
			}

			var verbs []string
			if allowRead {
				verbs = append(verbs, "msg.read")
			}
			if allowListen {
				verbs = append(verbs, "msg.listen")
			}

			issued, err := client.CreateAccessGrant(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}, client.CreateAccessGrantOptions{
				TargetNode:  loc.Node,
				SessionID:   loc.ID,
				SessionName: loc.Name,
				Audience:    audience,
				Verbs:       verbs,
				TTL:         ttl,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(issued)
			}

			target := formatAccessTarget(loc.Node, loc.ID, loc.Name)
			verbLabel := formatGrantVerbs(issued.Verbs)
			audienceLabel := issued.AudienceDisplay
			if strings.TrimSpace(audienceLabel) == "" {
				audienceLabel = issued.AudienceSubjectID
			}
			fmt.Fprintf(os.Stdout, "Granted %s on %s to %s for %s.\n", verbLabel, target, audienceLabel, ttlOrDefault(ttl))
			fmt.Fprintf(os.Stdout, "Grant ID: %s\n", issued.GrantID)
			fmt.Fprintf(os.Stdout, "Expires: %s\n", issued.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintf(os.Stdout, "Token: %s\n", issued.Delegation)
			return nil
		},
	}

	cmd.Flags().StringVar(&audience, "to", "", "Audience principal or exact username")
	cmd.Flags().StringVar(&ttl, "for", "", "Grant time-to-live (default: 10m)")
	cmd.Flags().BoolVar(&allowRead, "read", false, "Allow inbox reads")
	cmd.Flags().BoolVar(&allowListen, "listen", false, "Allow live listen")
	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to grant within (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func accessDropCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drop <grant-id>",
		Short: "Remove one accepted access grant from the local cache",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := client.RemoveAcceptedAccessGrant(dataDir(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Dropped accepted access grant %q\n", args[0])
			return nil
		},
	}
	return cmd
}

func accessInspectCmd() *cobra.Command {
	var (
		output    string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "inspect <grant-id>",
		Short: "Inspect one accepted access grant from the local cache",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			_, _ = client.PruneAcceptedAccessGrants(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			})
			grant, err := client.GetAcceptedAccessGrant(dataDir(), args[0])
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(grant)
			}
			fmt.Fprintf(os.Stdout, "Grant ID: %s\n", grant.GrantID)
			fmt.Fprintf(os.Stdout, "Target: %s\n", formatAccessTarget(grant.TargetNode, grant.SessionID, grant.SessionName))
			fmt.Fprintf(os.Stdout, "Network: %s\n", grant.NetworkID)
			fmt.Fprintf(os.Stdout, "Verbs: %s\n", formatGrantVerbs(grant.Verbs))
			fmt.Fprintf(os.Stdout, "Audience: %s:%s\n", grant.AudienceSubjectKind, grant.AudienceSubjectID)
			fmt.Fprintf(os.Stdout, "Accepted: %s\n", grant.AcceptedAt.Format(time.RFC3339))
			fmt.Fprintf(os.Stdout, "Expires: %s\n", grant.ExpiresAt.Format(time.RFC3339))
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to validate against before inspecting (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func accessListCmd() *cobra.Command {
	var (
		audience   string
		nodeName   string
		session    string
		verb       string
		activeOnly bool
		mine       bool
		accepted   bool
		output     string
		networkID  string
		relayURL   string
		authToken  string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued remote access grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			if accepted {
				if mine || strings.TrimSpace(audience) != "" || activeOnly {
					return fmt.Errorf("--accepted cannot be combined with remote grant filters")
				}
				_, _ = client.PruneAcceptedAccessGrants(dataDir(), client.RelayAuthOptions{
					RelayURL:  relayURL,
					AuthToken: authToken,
					NetworkID: networkID,
				})
				grants, err := client.ListAcceptedAccessGrantsFiltered(dataDir(), client.ListAcceptedAccessGrantOptions{
					NetworkID:   networkID,
					TargetNode:  nodeName,
					SessionName: session,
					Verb:        verb,
				})
				if err != nil {
					return err
				}
				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(grants)
				}
				if len(grants) == 0 {
					fmt.Println("No accepted access grants")
					return nil
				}
				fmt.Printf("%-14s %-24s %-12s %-20s\n", "ID", "TARGET", "VERBS", "EXPIRES")
				for _, grant := range grants {
					fmt.Printf(
						"%-14s %-24s %-12s %-20s\n",
						grant.GrantID,
						formatAccessTarget(grant.TargetNode, grant.SessionID, grant.SessionName),
						formatGrantVerbs(grant.Verbs),
						grant.ExpiresAt.Format(time.RFC3339),
					)
				}
				return nil
			}
			if mine && strings.TrimSpace(audience) != "" {
				return fmt.Errorf("--mine cannot be combined with --to")
			}
			if strings.TrimSpace(session) != "" || strings.TrimSpace(verb) != "" {
				return fmt.Errorf("--session and --verb require --accepted")
			}
			grants, err := client.ListAccessGrants(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}, client.ListAccessGrantOptions{
				TargetNode: nodeName,
				Audience:   audience,
				ActiveOnly: activeOnly,
				Mine:       mine,
			})
			if err != nil {
				return err
			}

			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(grants)
			}
			if len(grants) == 0 {
				fmt.Println("No access grants")
				return nil
			}

			fmt.Printf("%-14s %-24s %-12s %-18s %-12s\n", "ID", "TARGET", "VERBS", "AUDIENCE", "STATUS")
			for _, grant := range grants {
				fmt.Printf(
					"%-14s %-24s %-12s %-18s %-12s\n",
					grant.ID,
					formatAccessGrantTarget(grant),
					formatGrantVerbs(grant.Verbs),
					formatGrantAudience(grant),
					formatGrantStatus(grant),
				)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&audience, "to", "", "Filter by audience principal or exact username")
	cmd.Flags().StringVar(&nodeName, "node", "", "Filter by target node")
	cmd.Flags().StringVar(&session, "session", "", "Filter accepted grants by session name")
	cmd.Flags().StringVar(&verb, "verb", "", "Filter accepted grants by verb (msg.read|msg.listen)")
	cmd.Flags().BoolVar(&activeOnly, "active", false, "Only show active, non-revoked grants")
	cmd.Flags().BoolVar(&mine, "mine", false, "List grants issued to the authenticated principal")
	cmd.Flags().BoolVar(&accepted, "accepted", false, "List locally accepted access grants")
	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to list within (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func accessPruneCmd() *cobra.Command {
	var (
		output    string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Prune expired or revoked accepted access grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			result, err := client.PruneAcceptedAccessGrants(dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}
			fmt.Fprintf(os.Stdout, "Pruned accepted grants: expired=%d revoked=%d missing=%d remaining=%d\n", result.RemovedExpired, result.RemovedRevoked, result.RemovedMissing, result.Remaining)
			if result.RelayChecked {
				fmt.Fprintln(os.Stdout, "Relay validation: enabled")
			} else {
				fmt.Fprintln(os.Stdout, "Relay validation: skipped")
			}
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to validate against (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func accessRevokeCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "revoke <grant-id>",
		Short: "Revoke a remote access grant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := client.RevokeAccessGrant(dataDir(), args[0], client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Revoked access grant %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the access grant (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func accessWatchCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Watch relay invalidation events for accepted access grants",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			defer signal.Stop(sigCh)
			go func() {
				<-sigCh
				cancel()
			}()

			return client.WatchAcceptedAccessGrants(ctx, dataDir(), client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network to watch within (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func formatAccessTarget(node string, sessionID *uint32, sessionName string) string {
	if sessionID != nil {
		return fmt.Sprintf("%s:%d", node, *sessionID)
	}
	return node + ":" + sessionName
}

func formatAccessGrantTarget(grant store.AccessGrant) string {
	return formatAccessTarget(grant.TargetNode, grant.SessionID, grant.SessionName)
}

func formatGrantVerbs(verbs []string) string {
	if len(verbs) == 0 {
		return "-"
	}
	labels := make([]string, 0, len(verbs))
	for _, verb := range verbs {
		switch verb {
		case "msg.read":
			labels = append(labels, "read")
		case "msg.listen":
			labels = append(labels, "listen")
		default:
			labels = append(labels, verb)
		}
	}
	return strings.Join(labels, ",")
}

func formatGrantAudience(grant store.AccessGrant) string {
	if strings.TrimSpace(grant.AudienceDisplay) != "" {
		return grant.AudienceDisplay
	}
	return grant.AudienceSubjectID
}

func formatGrantStatus(grant store.AccessGrant) string {
	now := time.Now().UTC()
	switch {
	case grant.RevokedAt != nil:
		return "revoked"
	case now.After(grant.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

func ttlOrDefault(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "10m"
	}
	return raw
}
