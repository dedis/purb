.PHONY: install example test simul padme-figures

install:
	go get -u -tags=vartime ./...

example:
	go run -tags=vartime example.go

test:
	$(MAKE) -C purb test
	$(MAKE) -C experiments-encoding test

simul:
	$(MAKE) -C experiments-encoding simul

padme-figures:
	$(MAKE) -C experiments-padding all

all: install test example