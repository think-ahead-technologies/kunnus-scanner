BINARY := bin/kunnus
PKG := ./...

.PHONY: all build test cover lint fmt vet tidy clean

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
