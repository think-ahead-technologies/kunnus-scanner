BINARY := bin/kunnus
PKG := ./...

.PHONY: all build test cover compliance fuzz lint fmt vet tidy clean

SBOMQS_VERSION ?= v1.3.0

# How long each fuzz target runs per invocation. CI overrides this with a short
# bound; run `make fuzz FUZZTIME=5m` locally to hunt harder.
FUZZTIME ?= 30s

# Every Fuzz* target, as "<package> <FuzzName>" pairs. `go test -fuzz` runs one
# target at a time, so each is invoked separately. Add new targets here.
FUZZ_TARGETS := \
	./internal/modustoolbox:FuzzParseLine \
	./internal/apkchecksum:FuzzDecodeQ1 \
	./internal/license:FuzzNormalize \
	./internal/license:FuzzClassify \
	./internal/ownership:FuzzParseDpkgList \
	./internal/ownership:FuzzParseApkInstalled \
	./internal/debiancopyright:FuzzLicensesFromCopyright \
	./internal/ecosystem:FuzzParseGoSum \
	./internal/ecosystem:FuzzParseCargoLock \
	./internal/ecosystem:FuzzParseRequirementsTxt \
	./internal/ecosystem:FuzzParseBunLock \
	./internal/ecosystem:FuzzParseYarnLock \
	./internal/ecosystem:FuzzParseNPMLock \
	./internal/ecosystem:FuzzParsePNPMLock \
	./internal/ecosystem:FuzzParseConanLock \
	./internal/ecosystem:FuzzParseGemfileLockChecksums \
	./internal/ecosystem:FuzzParseNuGetLock \
	./internal/ecosystem:FuzzParseUvLock \
	./internal/ecosystem:FuzzParsePipfileLock \
	./internal/ecosystem:FuzzParseStackYamlLock \
	./internal/ecosystem:FuzzParsePyPIPackagesFilesLock \
	./internal/ecosystem:FuzzParseComposerLockHashes \
	./internal/ecosystem:FuzzParsePackageJSONLicense \
	./internal/ecosystem:FuzzParseWheelMetadataLicense \
	./internal/ecosystem:FuzzParseRockspecLicense \
	./internal/ecosystem:FuzzParseGemspecLicense \
	./internal/ecosystem:FuzzParseJavaArchiveLicense

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
	$(BINARY) sbom repo testdata/ecosystems -o /tmp/repo.cdx.json
	$(BINARY) sbom os --target-os linux testdata/osfamilies/alpine -o /tmp/os.cdx.json
	@echo "== repo SBOM ==" && sbomqs compliance --bsi-v2 /tmp/repo.cdx.json
	@echo "== os SBOM (apk licences) ==" && sbomqs compliance --bsi-v2 /tmp/os.cdx.json

# Run every fuzz target for FUZZTIME each. `-run='^$$'` skips the unit tests so
# only fuzzing runs; the seed corpus still executes as part of each fuzz target.
# `-fuzzminimizetime=1x` bounds input minimization to one run: minimization only
# shrinks inputs for human readability, and left at its 60s default it can
# straddle the -fuzztime deadline, failing the target with a spurious
# "context deadline exceeded" (golang/go#48157).
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		pkg=$${target%%:*}; name=$${target##*:}; \
		echo "== fuzzing $$name in $$pkg for $(FUZZTIME) =="; \
		go test -run='^$$' -fuzz="^$$name$$" -fuzztime=$(FUZZTIME) -fuzzminimizetime=1x $$pkg || exit 1; \
	done

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
