.PHONY: all example test install-experiments simul padme-figures

all: example test

example:
	cd example && go build && ./example

test:
	cd purbs && go test
	cd experiments-encoding/pgp && go test

# only needed for experiments

install-experiments:
	pip install -r requirements.txt

simul: install-experiments
	$(MAKE) -C experiments-encoding simul

padme-figures: install-experiments
	$(MAKE) -C experiments-padding all
