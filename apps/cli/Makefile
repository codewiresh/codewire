.PHONY: build test test-cli test-all smoke test-manual lint clean install \
       install-user install-user-unmanaged install-system path-note

REPO_ROOT := $(abspath ../..)
BINARY := cw
REQUESTED_CARGO_TARGET_DIR := $(CARGO_TARGET_DIR)
RESOLVED_CARGO_TARGET_DIR := $(shell cd "$(REPO_ROOT)" && CARGO_TARGET_DIR="$(REQUESTED_CARGO_TARGET_DIR)" scripts/ci/verify/resolve-cargo-target-dir.sh .)
USER_BIN_DIR ?= $(if $(strip $(XDG_BIN_HOME)),$(XDG_BIN_HOME),$(HOME)/.local/bin)
SYSTEM_BIN_DIR ?= /usr/local/bin
# The build records this checkout's version, source revision, source digest,
# target and compiler in cw; `cw install --managed` refuses a cw without them.
build:
	cd "$(REPO_ROOT)" && CARGO_TARGET_DIR="$(RESOLVED_CARGO_TARGET_DIR)" python3 scripts/dev/build-cw.py --output "$(CURDIR)/$(BINARY)"

test:
	cd $(REPO_ROOT) && cargo test -p codewire-cli

test-cli: test

test-all: test smoke

smoke: build
	./$(BINARY) --help >/dev/null
	./$(BINARY) env --help >/dev/null
	./$(BINARY) run --help >/dev/null
	./$(BINARY) list --help >/dev/null
	./$(BINARY) mesh --help >/dev/null
	./$(BINARY) network --help >/dev/null

test-manual: smoke

lint:
	cd $(REPO_ROOT) && cargo clippy -p codewire-cli --all-targets -- -D warnings

install: install-user

# Add this build as an immutable version behind the managed $(USER_BIN_DIR)/cw
# entry. Running cw processes keep their version; `cw update rollback` selects
# the previous one. An existing regular-file cw is refused, never replaced.
install-user: smoke
	@test -n "$(USER_BIN_DIR)" || { echo "USER_BIN_DIR is empty; set HOME, XDG_BIN_HOME, or USER_BIN_DIR" >&2; exit 1; }
	install -d "$(USER_BIN_DIR)"
	./$(BINARY) install --managed --bin-dir "$(USER_BIN_DIR)"
	@$(MAKE) --no-print-directory path-note

# Previous behavior: overwrite a regular-file cw in place. Processes and saved
# commands that use that path run the new bytes afterwards.
install-user-unmanaged: smoke
	@test -n "$(USER_BIN_DIR)" || { echo "USER_BIN_DIR is empty; set HOME, XDG_BIN_HOME, or USER_BIN_DIR" >&2; exit 1; }
	install -d "$(USER_BIN_DIR)"
	install -m 0755 "$(BINARY)" "$(USER_BIN_DIR)/$(BINARY)"
	@echo "Installed $(BINARY) to $(USER_BIN_DIR)/$(BINARY)"
	@$(MAKE) --no-print-directory path-note

path-note:
	@path_found=false; old_ifs=$$IFS; IFS=:; \
	for dir in $${PATH:-}; do \
		if [ "$$dir" = "$(USER_BIN_DIR)" ]; then path_found=true; break; fi; \
	done; \
	IFS=$$old_ifs; \
	if [ "$$path_found" != true ]; then \
		echo "Note: add $(USER_BIN_DIR) to PATH to run $(BINARY) by name."; \
	fi

install-system: smoke
	@if { [ -d "$(SYSTEM_BIN_DIR)" ] && [ -w "$(SYSTEM_BIN_DIR)" ]; } || \
	    { [ ! -e "$(SYSTEM_BIN_DIR)" ] && [ -w "$$(dirname "$(SYSTEM_BIN_DIR)")" ]; }; then \
		install -d "$(SYSTEM_BIN_DIR)"; \
		install -m 0755 "$(BINARY)" "$(SYSTEM_BIN_DIR)/$(BINARY)"; \
	elif command -v sudo >/dev/null 2>&1; then \
		sudo install -d "$(SYSTEM_BIN_DIR)"; \
		sudo install -m 0755 "$(BINARY)" "$(SYSTEM_BIN_DIR)/$(BINARY)"; \
	else \
		echo "Cannot write $(SYSTEM_BIN_DIR) and sudo is unavailable." >&2; \
		echo "Install manually, or run 'make cli-install-user' from the repository root." >&2; \
		exit 1; \
	fi
	@echo "Installed $(BINARY) to $(SYSTEM_BIN_DIR)/$(BINARY)"

clean:
	rm -f $(BINARY)
