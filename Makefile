BINARY := kvstore
VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build build-all test lint vet clean

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/kvstore

build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/kvstore
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64 ./cmd/kvstore
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64 ./cmd/kvstore
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64 ./cmd/kvstore
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-windows-amd64.exe ./cmd/kvstore
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-windows-arm64.exe ./cmd/kvstore

test:
	go test ./... -v -race -count=1

lint:
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
