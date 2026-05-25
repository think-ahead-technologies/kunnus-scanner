BINARY := bin/kunnus
PKG := ./...

.PHONY: all build test lint fmt vet tidy clean

all: fmt vet lint test build

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/kunnus

test:
	go test -race -count=1 $(PKG)

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
