.PHONY: all tidy lint vet test coverage

# Default "make" target to check locally that everything is ok, BEFORE pushing remotely
all: lint vet test
	@echo "Done with the standard checks"

tidy:
	# Tidy up go modules
	@go mod tidy

# Some packages are excluded from staticcheck due to deprecated warnings: #208.
lint: tidy
	# Coding style static check.
	@golangci-lint run

vet: tidy
	# Go vet
	@go vet ./...

test: tidy
	# Test without coverage
	@go test ./...

coverage: tidy
	# Test and generate a coverage output usable by sonarcloud
	@go test -json -covermode=count -coverpkg=./... -coverprofile=profile.cov ./... | tee report.json
