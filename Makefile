.PHONY: build test lint licenses postgres-up postgres-down test-postgres-counter

GOLANGCI_LINT_CACHE ?= $(CURDIR)/.cache/golangci-lint
export GOLANGCI_LINT_CACHE
POSTGRES_TEST_DSN ?= postgres://admin:secretpassword@localhost:5432/openiotrsp?sslmode=disable

build:
	go build ./...

test:
	go test ./...

lint:
	golangci-lint run

licenses:
	go-licenses check ./...

postgres-up:
	docker compose -f "$(CURDIR)/docker-compose.yml" up -d postgres
	until docker compose -f "$(CURDIR)/docker-compose.yml" exec -T postgres pg_isready -U admin -d openiotrsp; do sleep 1; done

postgres-down:
	docker compose -f "$(CURDIR)/docker-compose.yml" down

test-postgres-counter: postgres-up
	OPENIOTRSP_POSTGRES_TEST_DSN='$(POSTGRES_TEST_DSN)' go test -v -tags integration ./storage/postgres -run TestEUICCPackageCounterConcurrentSameEID -count=1
