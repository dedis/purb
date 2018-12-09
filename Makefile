.PHONY: install example demo test simul padme-figures clean

install:
	go get -u -tags=vartime -v ./...

example:
	go run -tags=vartime example/example.go

demo: example

test:
	$(MAKE) -C purbs test

simul:
	$(MAKE) -C experiments-encoding all

padme-figures:
	$(MAKE) -C experiments-padding all

lint:
	$(MAKE) -C purbs lint

clean:
	rm -f simul_*.txt

all: install test example