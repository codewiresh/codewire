SHELL := /bin/bash
export TMPDIR ?= /home/user/tmp

.PHONY: dev test build clean

dev:
	xtool dev

test:
	mkdir -p "$(TMPDIR)"
	TMPDIR="$(TMPDIR)" swift test

build:
	swift build

clean:
	rm -rf .build xtool
