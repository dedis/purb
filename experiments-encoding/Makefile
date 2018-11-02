.PHONY: install test simul
install:
	go get -u -tags=vartime -v ./...

test:
	cd pgp && go test -v -race *

simul:
	go run -tags=vartime simulation.go