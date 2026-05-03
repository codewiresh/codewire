package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	osExec "os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	cwconfig "github.com/codewiresh/codewire/internal/config"
)

func localFilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "files",
		Short: "Upload, download, and list files inside a local runtime instance",
	}
	cmd.AddCommand(localFilesUploadCmd())
	cmd.AddCommand(localFilesDownloadCmd())
	cmd.AddCommand(localFilesListCmd())
	return cmd
}

func localFilesUploadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload <name> <remote-path>",
		Short: "Upload bytes from stdin to a path inside a local runtime instance",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			instance, err := resolveLocalInstanceArg(args[0])
			if err != nil {
				return err
			}
			remotePath := args[1]
			if err := localFilesUpload(instance, remotePath, os.Stdin); err != nil {
				return err
			}
			if jsonOutput {
				return emitJSON(map[string]any{
					"name":        instance.Name,
					"remote_path": remotePath,
					"uploaded":    true,
				})
			}
			return nil
		},
	}
}

func localFilesDownloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "download <name> <remote-path>",
		Short: "Download a file from a local runtime instance to stdout",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := resolveLocalInstanceArg(args[0])
			if err != nil {
				return err
			}
			return localFilesDownload(instance, args[1], os.Stdout)
		},
	}
}

func localFilesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <name> [remote-path]",
		Short: "List directory entries at a path inside a local runtime instance",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := localOutputJSON(cmd)
			if err != nil {
				return err
			}
			instance, err := resolveLocalInstanceArg(args[0])
			if err != nil {
				return err
			}
			path := "/"
			if len(args) == 2 {
				path = args[1]
			}
			entries, err := localFilesList(instance, path)
			if err != nil {
				return err
			}
			if jsonOutput {
				return emitJSON(entries)
			}
			for _, e := range entries {
				kind := "file"
				if e.IsDir {
					kind = "dir"
				}
				fmt.Printf("%s\t%s\t%d\t%s\n", kind, e.Mode, e.Size, e.Name)
			}
			return nil
		},
	}
}

// localFileEntry is the schema for file list output. Stable for SDK consumers.
type localFileEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir"`
	Mode  string `json:"mode,omitempty"`
	Mtime string `json:"mtime,omitempty"`
}

// localFilesExecCmd returns a subprocess that will execute `argv` inside the
// local VM for the given backend. The subprocess has stdin/stdout wired to the
// caller — use cmd.StdinPipe / StdoutPipe to stream bytes.
//
// Supported: docker, lima. Other backends return an error.
func localFilesExecCmd(instance *cwconfig.LocalInstance, argv []string) (*osExec.Cmd, error) {
	switch instance.Backend {
	case "docker":
		args := []string{"exec", "-i", instance.RuntimeName}
		args = append(args, argv...)
		return osExec.Command("docker", args...), nil
	case "lima":
		name := limaInstanceName(instance)
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("missing Lima instance name for %s", instance.Name)
		}
		args := []string{"shell", "--workdir", "/", name, "sudo", "docker", "exec", "-i", limaContainerName}
		args = append(args, argv...)
		return osExec.Command("limactl", args...), nil
	case "incus", "firecracker":
		return nil, fmt.Errorf("cw local files is not yet supported for the %s backend", instance.Backend)
	default:
		return nil, fmt.Errorf("unsupported local backend %q", instance.Backend)
	}
}

// localFilesUpload streams src into remotePath inside the local VM. The parent
// directory is created if missing. Uses `sh -c 'mkdir -p … && cat > …'`.
func localFilesUpload(instance *cwconfig.LocalInstance, remotePath string, src io.Reader) error {
	if strings.TrimSpace(remotePath) == "" {
		return fmt.Errorf("remote path is required")
	}
	quoted := shellQuote(remotePath)
	parent := shellQuote(parentDir(remotePath))
	script := fmt.Sprintf("mkdir -p %s && cat > %s", parent, quoted)
	cmd, err := localFilesExecCmd(instance, []string{"sh", "-c", script})
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}
	copyErr := copyAndClose(stdin, src)
	waitErr := cmd.Wait()
	if copyErr != nil {
		return fmt.Errorf("upload: %w", copyErr)
	}
	if waitErr != nil {
		return fmt.Errorf("upload: %w", waitErr)
	}
	return nil
}

// localFilesDownload streams remotePath from the local VM into dst.
func localFilesDownload(instance *cwconfig.LocalInstance, remotePath string, dst io.Writer) error {
	if strings.TrimSpace(remotePath) == "" {
		return fmt.Errorf("remote path is required")
	}
	cmd, err := localFilesExecCmd(instance, []string{"cat", remotePath})
	if err != nil {
		return err
	}
	cmd.Stdout = dst
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	return nil
}

// localFilesList enumerates entries at remotePath. Uses `ls -la
// --time-style=full-iso` and parses each line. Directory entries "." and ".."
// are elided.
func localFilesList(instance *cwconfig.LocalInstance, remotePath string) ([]localFileEntry, error) {
	if strings.TrimSpace(remotePath) == "" {
		remotePath = "/"
	}
	cmd, err := localFilesExecCmd(instance, []string{"ls", "-la", "--time-style=full-iso", remotePath})
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}

	entries, parseErr := parseLsOutput(stdout)
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, fmt.Errorf("list: parse: %w", parseErr)
	}
	if waitErr != nil {
		return nil, fmt.Errorf("list: %w", waitErr)
	}
	return entries, nil
}

// parseLsOutput reads `ls -la --time-style=full-iso` output and produces a
// slice of localFileEntry. Skips the "total" header and "."/".." entries.
func parseLsOutput(r io.Reader) ([]localFileEntry, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var entries []localFileEntry
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "total ") || strings.TrimSpace(line) == "" {
			continue
		}
		// Fields: mode links owner group size date time tz name
		// Split on whitespace, but preserve the tail (name) which may contain spaces.
		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}
		mode := parts[0]
		size, _ := strconv.ParseInt(parts[4], 10, 64)
		mtime := strings.Join(parts[5:8], " ")
		// The name is everything from the 9th field onward. We need to rejoin
		// because strings.Fields collapses whitespace; use the original line.
		name := extractLsName(line, parts[:8])
		if name == "." || name == ".." {
			continue
		}
		// ls renders symlinks as "link -> target" — keep the link name.
		if idx := strings.Index(name, " -> "); idx >= 0 {
			name = name[:idx]
		}
		entries = append(entries, localFileEntry{
			Name:  name,
			Size:  size,
			IsDir: strings.HasPrefix(mode, "d"),
			Mode:  mode,
			Mtime: mtime,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// extractLsName returns the tail of an `ls -la` line after the first N
// whitespace-separated fields (the metadata prefix).
func extractLsName(line string, prefix []string) string {
	rest := line
	for _, f := range prefix {
		idx := strings.Index(rest, f)
		if idx < 0 {
			return rest
		}
		rest = rest[idx+len(f):]
	}
	return strings.TrimLeft(rest, " \t")
}

// parentDir returns everything before the last slash in remotePath, or "/" when
// the path has no parent component.
func parentDir(remotePath string) string {
	idx := strings.LastIndex(remotePath, "/")
	if idx <= 0 {
		return "/"
	}
	return remotePath[:idx]
}

// shellQuote wraps s in single quotes for POSIX sh. Embedded single quotes are
// escaped using the standard '\” pattern.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// copyAndClose copies src into dst and always closes dst, returning the first
// non-nil error.
func copyAndClose(dst io.WriteCloser, src io.Reader) error {
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
