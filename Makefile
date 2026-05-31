.PHONY: build test lint licenses

GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint
export GOLANGCI_LINT_CACHE

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

licenses:
	go-licenses check ./...
