.PHONY: install example demo test simul padme-figures

install:
	go get -u -tags=vartime -v ./...

example:
	go run -tags=vartime example.go

demo: example

test:
	$(MAKE) -C purbs test
	$(MAKE) -C experiments-encoding test

simul:
	$(MAKE) -C experiments-encoding simul

padme-figures:
	$(MAKE) -C experiments-padding all

lint:
	$(MAKE) -C purbs lint

all: install test example