.PHONY: simul clean

simul:
	go run -tags=vartime simul.go e > encode.json
	go run -tags=vartime simul.go d > decode.json
	go run -tags=vartime simul.go h > header_sizes.json
	go run -tags=vartime simul.go p > encode_precise.json
	go run -tags=vartime simul.go c > compactness.json

plot:
	python3 plot.py

clean:
	rm -f *.json