package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/codewiresh/codewire/internal/tui"
)

// isTTY returns true if stdin is a terminal (bubbletea prompts require it).
var isTTY = term.IsTerminal(int(os.Stdin.Fd()))

// prompt reads a line of input from the terminal.
func prompt(label string) (string, error) {
	if isTTY {
		return tui.Prompt(label)
	}
	// Fallback for piped input
	fmt.Print(label)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("interrupted")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// promptDefault reads a line of input with a default value shown in brackets.
func promptDefault(label, defaultVal string) (string, error) {
	if isTTY {
		return tui.PromptDefault(label, defaultVal)
	}
	// Fallback for piped input
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("interrupted")
	}
	val := strings.TrimSpace(scanner.Text())
	if val == "" {
		return defaultVal, nil
	}
	return val, nil
}

// promptPassword reads a password without echoing.
func promptPassword(label string) (string, error) {
	if isTTY {
		return tui.PromptPassword(label)
	}
	// Fallback for piped input (no echo control possible)
	fmt.Print(label)
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("interrupted")
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// promptSelect displays an interactive selection list and returns the selected index.
func promptSelect(label string, options []string) (int, error) {
	if isTTY {
		return tui.PromptSelect(label, options)
	}
	// Fallback for piped input: numbered list
	fmt.Println(label)
	for i, opt := range options {
		fmt.Printf("  [%d] %s\n", i+1, opt)
	}
	for {
		choice, err := prompt("Select: ")
		if err != nil {
			return 0, err
		}
		for i := range options {
			if choice == fmt.Sprintf("%d", i+1) {
				return i, nil
			}
		}
		fmt.Println("Invalid selection, try again.")
	}
}
