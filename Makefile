SHELL := /bin/bash

BIN_DIR  := bin
BIN_FILE := auth-service
PKG      := github.com/darkrain/auth-service

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo "dev")
BUILD    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS  := -ldflags "-X main.Version=$(VERSION) -X main.Build=$(BUILD) -X main.ProjectName=$(BIN_FILE)"

.PHONY: get vendor build test run install uninstall clean deb swagger

get:
	go mod download

vendor:
	go mod vendor

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BIN_FILE) ./cmd/main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BIN_FILE)-arm64 ./cmd/main.go

test:
	go test ./...

run:
	go run ./cmd/main.go --config debug.local.json

install: build
	install -D -m 0755 $(BIN_DIR)/$(BIN_FILE) /usr/bin/$(BIN_FILE)
	install -D -m 0644 auth-service.service /etc/systemd/system/auth-service.service
	install -d /etc/auth-service
	@if [ ! -f /etc/auth-service/config.json ]; then \
		install -D -m 0600 auth-service.example.json /etc/auth-service/config.json; \
		echo "Installed default config to /etc/auth-service/config.json — please edit it!"; \
	fi
	systemctl daemon-reload

uninstall:
	systemctl stop auth-service 2>/dev/null || true
	systemctl disable auth-service 2>/dev/null || true
	rm -f /usr/bin/$(BIN_FILE)
	rm -f /etc/systemd/system/auth-service.service
	systemctl daemon-reload

clean:
	rm -rf $(BIN_DIR)

swagger:
	swag init -g cmd/main.go -o docs/

deb: build
	$(eval DEB_AMD64 := $(BIN_FILE)_$(VERSION)_amd64)
	mkdir -p /tmp/$(DEB_AMD64)/DEBIAN
	chmod 0755 /tmp/$(DEB_AMD64)/DEBIAN
	mkdir -p /tmp/$(DEB_AMD64)/usr/bin
	mkdir -p /tmp/$(DEB_AMD64)/etc/systemd/system
	mkdir -p /tmp/$(DEB_AMD64)/etc/auth-service
	install -m 0755 $(BIN_DIR)/$(BIN_FILE) /tmp/$(DEB_AMD64)/usr/bin/$(BIN_FILE)
	install -m 0644 auth-service.service /tmp/$(DEB_AMD64)/etc/systemd/system/auth-service.service
	install -m 0600 auth-service.example.json /tmp/$(DEB_AMD64)/etc/auth-service/config.json
	printf 'Package: $(BIN_FILE)\nVersion: $(VERSION)\nArchitecture: amd64\nMaintainer: darkrain\nDescription: auth-service\n' \
		> /tmp/$(DEB_AMD64)/DEBIAN/control
	dpkg-deb --build /tmp/$(DEB_AMD64) $(BIN_DIR)/$(DEB_AMD64).deb
	rm -rf /tmp/$(DEB_AMD64)
	@echo "Built: $(BIN_DIR)/$(DEB_AMD64).deb"
	$(eval DEB_ARM64 := $(BIN_FILE)_$(VERSION)_arm64)
	mkdir -p /tmp/$(DEB_ARM64)/DEBIAN
	chmod 0755 /tmp/$(DEB_ARM64)/DEBIAN
	mkdir -p /tmp/$(DEB_ARM64)/usr/bin
	mkdir -p /tmp/$(DEB_ARM64)/etc/systemd/system
	mkdir -p /tmp/$(DEB_ARM64)/etc/auth-service
	install -m 0755 $(BIN_DIR)/$(BIN_FILE)-arm64 /tmp/$(DEB_ARM64)/usr/bin/$(BIN_FILE)
	install -m 0644 auth-service.service /tmp/$(DEB_ARM64)/etc/systemd/system/auth-service.service
	install -m 0600 auth-service.example.json /tmp/$(DEB_ARM64)/etc/auth-service/config.json
	printf 'Package: $(BIN_FILE)\nVersion: $(VERSION)\nArchitecture: arm64\nMaintainer: darkrain\nDescription: auth-service\n' \
		> /tmp/$(DEB_ARM64)/DEBIAN/control
	dpkg-deb --build /tmp/$(DEB_ARM64) $(BIN_DIR)/$(DEB_ARM64).deb
	rm -rf /tmp/$(DEB_ARM64)
	@echo "Built: $(BIN_DIR)/$(DEB_ARM64).deb"
