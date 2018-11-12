.PHONY: install test testlong lint

install:
	go get -u -tags=vartime -v ./...

test:
	DEBUG_COLOR=true DEBUG_LEVEL=3 go test -v -race -test.short -tags=vartime *.go

testlong:
	DEBUG_COLOR=true DEBUG_LEVEL=3 go test -v -race -tags=vartime *.go

lint:
	go fmt *.go
	@{ \
		exclude="_test.go|ALL_CAPS|underscore|should be of the form|.deprecated|and that stutters|error strings should not be capitalized"; \
		lintfiles=$$( golint ./... | egrep -v "($$exclude)" ); \
		if [ -n "$$lintfiles" ]; then \
		echo "Lint errors:"; \
		echo "$$lintfiles"; \
		exit 1; \
		fi \
	}