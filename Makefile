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
	gosec ./...
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

# Run ci tests
test-ci: test
	goveralls -service=travis-ci -v -coverprofile=coverage.out

release: tools
	goreleaser --rm-dist

test-release: tools
	goreleaser --skip-publish --snapshot --rm-dist

tools:
ifeq (, $(shell which goreleaser))
 $(shell go get github.com/goreleaser/goreleaser)
endif
ifeq (, $(shell which gosec))
 $(shell go get -u github.com/securego/gosec/v2/cmd/gosec)
endif
