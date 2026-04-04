SHELL := /bin/bash

BIN_DIR  := bin
BIN_FILE := auth-service
PKG      := github.com/darkrain/auth-service

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS  := -ldflags "-X main.Version=$(VERSION) -X main.Build=$(BUILD) -X main.ProjectName=$(BIN_FILE)"

.PHONY: get vendor build test run install uninstall clean deb

get:
	go mod download

vendor:
	go mod vendor

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BIN_FILE) ./cmd/main.go

test:
	go test ./...

run:
	go run ./cmd/main.go --config auth-service.example.json

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

deb: build
	$(eval DEB_NAME := $(BIN_FILE)_$(VERSION)_amd64)
	mkdir -p /tmp/$(DEB_NAME)/DEBIAN
	mkdir -p /tmp/$(DEB_NAME)/usr/bin
	mkdir -p /tmp/$(DEB_NAME)/etc/systemd/system
	mkdir -p /tmp/$(DEB_NAME)/etc/auth-service
	install -m 0755 $(BIN_DIR)/$(BIN_FILE) /tmp/$(DEB_NAME)/usr/bin/$(BIN_FILE)
	install -m 0644 auth-service.service /tmp/$(DEB_NAME)/etc/systemd/system/auth-service.service
	install -m 0600 auth-service.example.json /tmp/$(DEB_NAME)/etc/auth-service/config.json
	printf 'Package: $(BIN_FILE)\nVersion: $(VERSION)\nArchitecture: amd64\nMaintainer: darkrain\nDescription: auth-service\n' \
		> /tmp/$(DEB_NAME)/DEBIAN/control
	dpkg-deb --build /tmp/$(DEB_NAME) $(BIN_DIR)/$(DEB_NAME).deb
	rm -rf /tmp/$(DEB_NAME)
	@echo "Built: $(BIN_DIR)/$(DEB_NAME).deb"
