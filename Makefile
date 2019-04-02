all: test radius-server

.PHONY: test

radius-server: vendor
	go build .

test: vendor
	go test -v ./...

vendor:
	dep ensure -vendor-only
