.PHONY:test
test:
	cd purbs && go test -v -race -tags=vartime *
	cd experiments-encoding/pgp && go test -v -race *

.PHONY: simul
simul:
	cd experiments-encoding && go run -tags=vartime simulation.go

.PHONY: example
example:
	go run -tags=vartime example.go