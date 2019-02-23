# Encoding experiments

You need matplotlib/numpy and go to run the experiments (do `make install` and `make install-experiments` on the main repo)

This folder contains:

- `Makefile` which wires everything
- `simul.go` which runs the go experiment and outputs `.json` data
- `plot.py` which processes the `.json` and produces plot
- `allowed_position.py` which is standalone and simply computes sets of allowed positions for suites, as defined in the paper