# Run go fmt against code
fmt:
	go fmt ./...
	gofmt -s -w .

# Run go vet against code
vet:
	go vet ./...

# Run go mod tidy
tidy:
	go mod tidy

# Run tests
test: tidy fmt vet
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run ci tests
test-ci: test
	goveralls -service=travis-ci -v -coverprofile=coverage.out

release: goreleaser semver
	@version=$$($(SEMVER)); \
	git tag -s $$version -m"Release $$version"
	$(GORELEASER) --clean

test-release: goreleaser
	$(GORELEASER) --skip=publish --snapshot --clean


## toolbox - start
## Current working directory
LOCALDIR ?= $(shell which cygpath > /dev/null 2>&1 && cygpath -m $$(pwd) || pwd)
## Location to install dependencies to
LOCALBIN ?= $(LOCALDIR)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
GORELEASER ?= $(LOCALBIN)/goreleaser
SEMVER ?= $(LOCALBIN)/semver

## Tool Installer
.PHONY: goreleaser
goreleaser: $(GORELEASER) ## Download goreleaser locally if necessary.
$(GORELEASER): $(LOCALBIN)
	test -s $(LOCALBIN)/goreleaser || GOBIN=$(LOCALBIN) go install github.com/goreleaser/goreleaser
.PHONY: semver
semver: $(SEMVER) ## Download semver locally if necessary.
$(SEMVER): $(LOCALBIN)
	test -s $(LOCALBIN)/semver || GOBIN=$(LOCALBIN) go install github.com/bakito/semver

## Update Tools
.PHONY: update-toolbox-tools
update-toolbox-tools:
	@rm -f \
		$(LOCALBIN)/goreleaser \
		$(LOCALBIN)/semver
	toolbox makefile -f $(LOCALDIR)/Makefile
## toolbox - end
