package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
	"github.com/codewiresh/codewire/internal/store"
)

func groupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage relay groups",
	}

	cmd.AddCommand(
		groupCreateCmd(),
		groupDeleteCmd(),
		groupListCmd(),
		groupMembersCmd(),
		groupAddCmd(),
		groupRemoveCmd(),
		groupPolicyCmd(),
	)
	return cmd
}

func groupCreateCmd() *cobra.Command {
	var (
		output    string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new group in the current network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			group, err := client.CreateGroup(dataDir(), args[0], client.RelayAuthOptions{
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
				return enc.Encode(group)
			}

			fmt.Fprintf(os.Stdout, "Created group %q in network %q.\n", group.Name, group.NetworkID)
			if group.Policy != nil {
				fmt.Fprintf(os.Stdout, "Policy: messages=%s debug=%s\n", group.Policy.MessagesPolicy, group.Policy.DebugPolicy)
			}
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to create within (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupDeleteCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete one group from the current network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := client.DeleteGroup(dataDir(), args[0], client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Deleted group %q\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the group (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupListCmd() *cobra.Command {
	var (
		output    string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List groups in the current network",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			groups, err := client.ListGroups(dataDir(), client.RelayAuthOptions{
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
				return enc.Encode(groups)
			}
			if len(groups) == 0 {
				fmt.Println("No groups")
				return nil
			}

			fmt.Printf("%-20s %-16s %-14s %-20s\n", "NAME", "MESSAGES", "DEBUG", "CREATED")
			for _, group := range groups {
				fmt.Printf(
					"%-20s %-16s %-14s %-20s\n",
					group.Name,
					formatGroupMessagesPolicy(group.Policy),
					formatGroupDebugPolicy(group.Policy),
					group.CreatedAt.Format(time.RFC3339),
				)
			}
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network to list within (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupMembersCmd() *cobra.Command {
	var (
		output    string
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "members <group>",
		Short: "Show members of one group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			group, err := client.GetGroup(dataDir(), args[0], client.RelayAuthOptions{
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
				return enc.Encode(group)
			}
			if len(group.Members) == 0 {
				fmt.Printf("Group %q has no members\n", group.Name)
				return nil
			}

			fmt.Printf("%-20s %-20s %-20s\n", "NODE", "SESSION", "ADDED")
			for _, member := range group.Members {
				fmt.Printf(
					"%-20s %-20s %-20s\n",
					member.NodeName,
					member.SessionName,
					member.CreatedAt.Format(time.RFC3339),
				)
			}
			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the group (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupAddCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "add <group> <node>:<session>",
		Short: "Add one named session to a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			loc, err := parseSessionLocator(args[1])
			if err != nil {
				return err
			}
			if !loc.isRemote() || loc.ID != nil {
				return fmt.Errorf("target must be <node>:<session>")
			}

			member, err := client.AddGroupMember(dataDir(), args[0], loc.Node, loc.Name, client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Added %s:%s to group %q\n", member.NodeName, member.SessionName, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the group (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupRemoveCmd() *cobra.Command {
	var (
		networkID string
		relayURL  string
		authToken string
	)

	cmd := &cobra.Command{
		Use:   "remove <group> <node>:<session>",
		Short: "Remove one named session from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			loc, err := parseSessionLocator(args[1])
			if err != nil {
				return err
			}
			if !loc.isRemote() || loc.ID != nil {
				return fmt.Errorf("target must be <node>:<session>")
			}

			if err := client.RemoveGroupMember(dataDir(), args[0], loc.Node, loc.Name, client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Removed %s:%s from group %q\n", loc.Node, loc.Name, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the group (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func groupPolicyCmd() *cobra.Command {
	var (
		messagesPolicy string
		debugPolicy    string
		output         string
		networkID      string
		relayURL       string
		authToken      string
	)

	cmd := &cobra.Command{
		Use:   "policy <group>",
		Short: "Show or update policy for one group",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			auth := client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}
			current, err := client.GetGroup(dataDir(), args[0], auth)
			if err != nil {
				return err
			}
			if current.Policy == nil {
				return fmt.Errorf("group %q has no policy", args[0])
			}

			if strings.TrimSpace(messagesPolicy) == "" && strings.TrimSpace(debugPolicy) == "" {
				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(current.Policy)
				}
				fmt.Fprintf(os.Stdout, "Group %q policy: messages=%s debug=%s\n", args[0], current.Policy.MessagesPolicy, current.Policy.DebugPolicy)
				return nil
			}

			nextMessages := current.Policy.MessagesPolicy
			if strings.TrimSpace(messagesPolicy) != "" {
				nextMessages = strings.TrimSpace(messagesPolicy)
			}
			nextDebug := current.Policy.DebugPolicy
			if strings.TrimSpace(debugPolicy) != "" {
				nextDebug = strings.TrimSpace(debugPolicy)
			}

			policy, err := client.SetGroupPolicy(dataDir(), args[0], auth, client.GroupPolicyUpdateOptions{
				MessagesPolicy: nextMessages,
				DebugPolicy:    nextDebug,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(policy)
			}
			fmt.Fprintf(os.Stdout, "Updated group %q policy: messages=%s debug=%s\n", args[0], policy.MessagesPolicy, policy.DebugPolicy)
			return nil
		},
	}

	cmd.Flags().StringVar(&messagesPolicy, "messages", "", "Message policy (internal-only|open)")
	cmd.Flags().StringVar(&debugPolicy, "debug", "", "Debug policy (none|observe-only|full)")
	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network containing the group (default: configured network)")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override (session token or token-mode admin token)")
	return cmd
}

func formatGroupMessagesPolicy(policy *store.GroupPolicy) string {
	if policy == nil || strings.TrimSpace(policy.MessagesPolicy) == "" {
		return "-"
	}
	return policy.MessagesPolicy
}

func formatGroupDebugPolicy(policy *store.GroupPolicy) string {
	if policy == nil || strings.TrimSpace(policy.DebugPolicy) == "" {
		return "-"
	}
	return policy.DebugPolicy
}
