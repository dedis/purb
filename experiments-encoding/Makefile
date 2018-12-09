
.PHONY: simul
simul:
	go run -tags=vartime simul.go e > encode.json
	go run -tags=vartime simul.go d > decode.json
	go run -tags=vartime simul.go g > decode_pgp.json
	go run -tags=vartime simul.go h > header_sizes.json