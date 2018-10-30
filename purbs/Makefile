.PHONY: install test

install:
	go get -u -tags=vartime ./...

test:
	go test -v -race -tags=vartime *.go
