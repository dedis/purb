.PHONY: simul clean plot-encode plot-encode-precise plot-decode plot-header-size plot-header-compactness

simul:
	go run -tags=vartime simul.go e > encode.json
	go run -tags=vartime simul.go d > decode.json
	go run -tags=vartime simul.go h > header_sizes.json
	go run -tags=vartime simul.go p > encode_precise.json
	go run -tags=vartime simul.go c > compactness.json

plot-encode:
	python3 plot.py e

plot-encode-precise:
	python3 plot.py p

plot-decode:
	python3 plot.py d

plot-header-size:
	python3 plot.py h

plot-header-compactness:
	python3 plot.py c

clean:
	rm -f *.json