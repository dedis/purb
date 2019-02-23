#!/usr/bin/python3
import sys
from math import *
import operator
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import math
import glob
from colors import *
from padme import *
from functools import reduce

# create the plot "fig4-i-$DATASET-anonymity-cdf.eps"
def computeOverheads(input_file):
    Ls = []             # the raw L's values
    Bs = []

    # Parse the input file, fills Ls, Ls_count, Ls_hist
    with open(input_file, "r") as f:
        for line in f:
            L = int(line.strip())
            if L == 0 or L == 1:
                continue
            Ls.append(L)

    # Compute overheads in percentage
    Bs = [float(getPadme(L) - L)/L for L in Ls]
    Ps = [float(math.pow(2, math.ceil(math.log(L, 2))) - L)/L for L in Ls]
    Qs = [float(L + (L % 256) - L)/L for L in Ls]
    Qs2 = [float(L + (L % (512 * 8)) - L)/L for L in Ls]

    def mean(Xs):
        mean = reduce(lambda x, y: x + y, Xs) / len(Xs)
        return round(mean * 10000) / float(100)

    meanOverheadBs = mean(Bs)
    meanOverheadPs = mean(Ps)
    meanOverheadQs = mean(Qs)
    meanOverheadQs2 = mean(Qs2)

    print(input_file, "\t", meanOverheadQs2, "\t", meanOverheadPs, "\t", meanOverheadBs)
    

for f in glob.iglob('./*.sizes'):
    dataset = f.replace('./', '').replace('.sizes', '')
    computeOverheads(f)
