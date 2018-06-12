#!/usr/bin/python3
import sys
from math import *
import operator
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
import math
from colors import *
from padme import *
import glob


import matplotlib

matplotlib.rcParams.update({'font.size': font_size})

def mean(vals):
    acc = 0.
    for v in vals:
        acc += v
    return acc / len(vals)

def computeDensity(data):
    histogram = {}
    for d in data:
        if str(d) not in histogram:
            histogram[str(d)] = 0
        histogram[str(d)] += 1
    densities = list(histogram.values())
    densities = np.sort(densities)
    return densities

def bucketize(values_and_count):
    groups = {}

    for size in values_and_count:
        count = values_and_count[size] # number of packets having size "size"

        size_log10 = int(math.floor(math.log(int(size), 2)))

        if str(size_log10) not in groups:
            groups[str(size_log10)] = []
        groups[str(size_log10)].append(count)

    buckets = {}
    for bucket in groups:
        counts = groups[bucket]

        total = len(counts)
        unique = 0
        for c in counts:
            if c < 3:
                unique += 1

        buckets[bucket] = [unique, total]

    return buckets

def extractCurves(buckets, minKey, maxXKey):
    percentageOfUniquePackets = [0] * (maxXKey + 1 - minKey)
    total = [0] * (maxXKey + 1 - minKey)

    i = minKey # 10^0

    while i <= maxXKey:
        if str(i) in buckets:
            nUnique = buckets[str(i)][0]
            nTotal = buckets[str(i)][1]
            percentageOfUniquePackets[i-minKey] = 100*float(nUnique)/float(nTotal)
        i+=1

    return percentageOfUniquePackets


def plot(j, input_file):
    plt.figure(j)
    Ls = []             # the raw L's values
    Ls_count = {}       # a dictionary [packet size] -> [number of packets with this size]

    with open(input_file, "r") as f:
        for line in f:
            L = int(line.strip())
            if L == 0 or L == 1:
                continue
            Ls.append(L)
            if str(L) not in Ls_count:
                Ls_count[str(L)] = 0
            Ls_count[str(L)] += 1

    Bs = [getPadme(L) for L in Ls]
    Ps = [int(math.pow(2, math.ceil(math.log(L, 2)))) for L in Ls]

    Bs_count = {}
    Ps_count = {}

    for B in Bs:
        if str(B) not in Bs_count:
            Bs_count[str(B)] = 0
        Bs_count[str(B)] += 1
    for P in Ps:
        if str(P) not in Ps_count:
            Ps_count[str(P)] = 0
        Ps_count[str(P)] += 1

    Ls_buckets = bucketize(Ls_count)
    Bs_buckets = bucketize(Bs_count)
    Ps_buckets = bucketize(Ps_count)

    minLsKey = min([int(x) for x in [*Ls_buckets.keys()]])
    minBsKey = min([int(x) for x in [*Bs_buckets.keys()]])
    minPsKey = min([int(x) for x in [*Ps_buckets.keys()]])
    minKey = min(minLsKey, min(minBsKey, minPsKey))

    maxLsKey = max([int(x) for x in [*Ls_buckets.keys()]])
    maxBsKey = max([int(x) for x in [*Bs_buckets.keys()]])
    maxPsKey = max([int(x) for x in [*Ps_buckets.keys()]])
    maxKey = max(maxLsKey, max(maxBsKey, maxPsKey))

    Ls_percentageUniquePackets = extractCurves(Ls_buckets, minKey, maxKey)
    Bs_percentageUniquePackets = extractCurves(Bs_buckets, minKey, maxKey)
    Ps_percentageUniquePackets = extractCurves(Ps_buckets, minKey, maxKey)

    legends = []

    xValues = []
    i=minLsKey
    while i<=maxKey:
        xValues.append(math.pow(2, i))
        i += 1

    plt.plot(xValues, Ls_percentageUniquePackets, color=unpadded_color, linestyle=unpadded_style, linewidth=curve_width)
    legends.append('Unpadded')

    plt.plot(xValues, Bs_percentageUniquePackets, color=padme_color, linestyle=padme_style, linewidth=curve_width)
    legends.append('Padmé')

    plt.plot(xValues, Ps_percentageUniquePackets, color=nextpow2_color, linestyle=nextpow2_style, linewidth=curve_width)
    legends.append('Pow2')

    #plt.title('Anonymity set w.r.t size, '+input_file)
    plt.xlabel('File sizes [bits]')
    plt.ylabel('Percentage of unique objects [%]')
    plt.legend(legends, loc='upper left')

    plt.xscale('log', basex=10)
    #plt.yscale('log')

    plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
    plt.tight_layout()
    dataset = input_file.replace('./', '').replace('.sizes', '')
    plt.savefig('fig5-'+str(j)+'-'+dataset+'-sizes-vs-anon-percentage.eps')

i=1
plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
for f in glob.iglob('./*.sizes'):
    dataset = f.replace('./', '').replace('.sizes', '')
    print("Plotting", 'fig5-'+str(i)+'-'+dataset+'-sizes-vs-anon-percentage.eps')
    plot(i, f)
    i += 1
