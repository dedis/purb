.PHONY: install example demo test simul padme-figures clean install-experiments

install:
	go get -u -tags=vartime -v ./...

demo: example
example:
	go run -tags=vartime example/example.go

test:
	$(MAKE) -C purbs test

lint:
	$(MAKE) -C purbs lint

clean:
	rm -f simul_*.txt

all: install test example

# only needed for experiments

install-experiments:
	pip install -r requirements.txt

simul: install-experiments
	$(MAKE) -C experiments-encoding simul

padme-figures: install-experiments
	$(MAKE) -C experiments-padding all
