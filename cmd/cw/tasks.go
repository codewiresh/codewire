package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/client"
)

var taskCmdStderr io.Writer = os.Stderr

func tasksCmd() *cobra.Command {
	var (
		output     string
		speak      bool
		watch      bool
		networkID  string
		nodeName   string
		sessionArg string
		state      string
		relayURL   string
		authToken  string
		voice      string
	)

	cmd := &cobra.Command{
		Use:   "tasks",
		Short: "List or watch relay task reports",
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID, err := parseTaskSessionFilter(sessionArg)
			if err != nil {
				return err
			}
			opts := client.WatchTasksOptions{
				NetworkID: networkID,
				NodeName:  nodeName,
				SessionID: sessionID,
				State:     state,
			}
			auth := client.RelayAuthOptions{
				RelayURL:  relayURL,
				AuthToken: authToken,
				NetworkID: networkID,
			}
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}

			if watch {
				return runTasksWatch(auth, opts, jsonOutput, speak, voice)
			}
			if speak {
				return fmt.Errorf("--speak requires --watch")
			}
			snapshots, err := client.ListTasks(dataDir(), auth, opts)
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(snapshots)
			}
			printTaskSnapshots(snapshots)
			return nil
		},
	}

	cmd.Flags().BoolVar(&watch, "watch", false, "Watch task events as they arrive")
	cmd.Flags().BoolVar(&speak, "speak", false, "Speak task summaries while watching")
	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&networkID, "network", "", "Network override")
	cmd.Flags().StringVar(&nodeName, "node", "", "Filter by node name")
	cmd.Flags().StringVar(&sessionArg, "session", "", "Filter by numeric session ID")
	cmd.Flags().StringVar(&state, "state", "", "Filter by state: working, complete, blocked, failed")
	cmd.Flags().StringVar(&relayURL, "relay-url", "", "Relay base URL override")
	cmd.Flags().StringVar(&authToken, "token", "", "Relay auth token override")
	cmd.Flags().StringVar(&voice, "voice", "", "Preferred speech voice name")
	return cmd
}

func runTasksWatch(auth client.RelayAuthOptions, opts client.WatchTasksOptions, jsonOutput, speak bool, voice string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	events := make(chan client.TaskEvent, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.WatchTasks(ctx, dataDir(), auth, opts, events)
	}()

	var speechQueue chan client.TaskEvent
	if speak {
		speaker, err := client.NewTaskSpeaker(client.TaskSpeakerOptions{Voice: voice})
		if err != nil {
			fmt.Fprintf(taskCmdStderr, "warning: %v\n", err)
		} else {
			speechQueue = make(chan client.TaskEvent, 4)
			go runTaskSpeech(ctx, speaker, speechQueue)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return <-errCh
		case err := <-errCh:
			return err
		case ev := <-events:
			if jsonOutput {
				if err := enc.Encode(ev); err != nil {
					return err
				}
				continue
			}
			printTaskEvent(ev)
			if speechQueue != nil {
				select {
				case speechQueue <- ev:
				default:
				}
			}
		}
	}
}

func runTaskSpeech(ctx context.Context, speaker client.TaskSpeaker, in <-chan client.TaskEvent) {
	lastSpoken := ""
	warned := false

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-in:
			text := client.TaskSpeechText(ev)
			if text == "" || text == lastSpoken {
				continue
			}
			if err := speaker.Speak(ctx, text); err != nil {
				if !warned {
					fmt.Fprintf(taskCmdStderr, "warning: task speech failed: %v\n", err)
					warned = true
				}
				continue
			}
			lastSpoken = text
		}
	}
}

func printTaskSnapshots(tasks []client.TaskSnapshot) {
	if len(tasks) == 0 {
		fmt.Println("No task reports")
		return
	}

	fmt.Printf("%-20s %-14s %-10s %-20s %s\n", "NODE", "SESSION", "STATE", "UPDATED", "SUMMARY")
	for _, task := range tasks {
		fmt.Printf(
			"%-20s %-14s %-10s %-20s %s\n",
			task.NodeName,
			taskSessionLabel(task.SessionID, task.SessionName),
			task.State,
			formatTaskTimestamp(task.Timestamp),
			task.Summary,
		)
	}
}

func printTaskEvent(ev client.TaskEvent) {
	if ev.Type == "stream.reset" {
		fmt.Printf("[%d] stream reset for %s\n", ev.Seq, ev.NetworkID)
		return
	}
	fmt.Printf(
		"[%s] %-20s %-14s %-10s %s\n",
		formatTaskTimestamp(ev.Timestamp),
		ev.NodeName,
		taskSessionLabel(ev.SessionID, ev.SessionName),
		ev.State,
		ev.Summary,
	)
}

func parseTaskSessionFilter(raw string) (*uint32, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || parsed == 0 {
		return nil, fmt.Errorf("--session must be a numeric session ID")
	}
	sessionID := uint32(parsed)
	return &sessionID, nil
}

func taskSessionLabel(sessionID uint32, sessionName string) string {
	if strings.TrimSpace(sessionName) != "" {
		return sessionName
	}
	return strconv.FormatUint(uint64(sessionID), 10)
}

func formatTaskTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "-"
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return parsed.Local().Format(time.RFC3339)
}
