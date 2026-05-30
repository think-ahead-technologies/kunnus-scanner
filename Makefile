BINARY := bin/kunnus
PKG := ./...

.PHONY: all build test cover compliance lint fmt vet tidy clean

SBOMQS_VERSION ?= v1.3.0

all: fmt vet lint test build

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/kunnus

test:
	go test -race -count=1 $(PKG)

# Coverage. -coverpkg spans the whole module so the command/ and mode/ wiring,
# which the cmd/kunnus e2e tests reach only by running the built binary, is
# attributed instead of reported as 0%. The e2e harness instruments that binary
# and merges its counters via GOCOVERDIR (see cmd/kunnus/main_test.go).
cover:
	go test -count=1 -coverpkg=$(PKG) -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -1

# BSI TR-03183-2 v2 conformance: generate an SBOM over the fixture corpus and
# score it with sbomqs. Mirrors the compliance CI job; run it before changing
# anything that affects SBOM field output to see the score move.
compliance: build
	go install github.com/interlynk-io/sbomqs@$(SBOMQS_VERSION)
	$(BINARY) sbom repo testdata/ecosystems -o /tmp/kunnus-sbom.json
	sbomqs compliance --bsi-v2 /tmp/kunnus-sbom.json

lint:
	golangci-lint run $(PKG)

fmt:
	gofmt -s -w .

vet:
	go vet $(PKG)

tidy:
	go mod tidy

clean:
	rm -rf bin
