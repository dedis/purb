#!/usr/bin/python3
import sys
from math import *
import operator
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
import math
import glob
from colors import *
from padme import *
import matplotlib

matplotlib.rcParams.update({'font.size': font_size})

def computeDensity(data):
    histogram = {}
    for d in data:
        if str(d) not in histogram:
            histogram[str(d)] = 0
        histogram[str(d)] += 1
    densities = list(histogram.values())
    densities = np.sort(densities)
    return densities

# create the plot "fig4-i-$DATASET-anonymity-cdf.eps"
def createFigDatasetAnonymityCDF(i, input_file):
    plt.figure(i)
    Ls = []             # the raw L's values
    Bs = []

    ## Parse the input file, fills Ls, Ls_count, Ls_hist
    with open(input_file, "r") as f:
        for line in f:
            L = int(line.strip())
            if L == 0 or L == 1:
                continue
            Ls.append(L)

    Bs = [getPadme(L) for L in Ls]
    Ps = [math.pow(2, math.ceil(math.log(L, 2))) for L in Ls]
    Qs = [L + (L % 256) for L in Ls]
    Qs2 = [L + (L % (512 * 8)) for L in Ls]

    legends = []

    data = computeDensity(Ls)
    p = 100. * np.arange(len(data)) / (len(data) - 1)
    plt.plot(data, p, color=unpadded_color, linestyle=unpadded_style, linewidth=curve_width)
    legends.append('Unpadded')

    #data = computeDensity(Qs)
    #p = 100. * np.arange(len(data)) / (len(data) - 1)
    #plt.plot(data, p, color=blockcipher_color, linestyle=blockcipher_style, linewidth=curve_width)
    #legends.append('Block cipher (256b)')

    data = computeDensity(Qs2)
    p = 100. * np.arange(len(data)) / (len(data) - 1)
    plt.plot(data, p, color=blockcipher_color, linestyle=blockcipher_style, linewidth=curve_width)
    legends.append('Tor cell (512B)')

    data = computeDensity(Bs)
    p = 100. * np.arange(len(data)) / (len(data) - 1)
    plt.plot(data, p, color=padme_color, linestyle=padme_style, linewidth=curve_width)
    legends.append('Padmé')

    data = computeDensity(Ps)
    p = 100. * np.arange(len(data)) / (len(data) - 1)
    plt.plot(data, p, color=nextpow2_color, linestyle=nextpow2_style, linewidth=curve_width)
    legends.append('Next power of 2')

    #plt.title('CDF of anonymity in the dataset '+input_file)
    plt.title('')

    plt.ylabel('Percentile')
    plt.xlabel('Anonymity set size')
    plt.legend(legends, loc='lower right')

    plt.xscale('log')
    #plt.yscale('log')

    plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
    plt.tight_layout()
    dataset = input_file.replace('./', '').replace('.sizes', '')
    plt.savefig('fig4-'+str(i)+'-'+dataset+'-anonymity-cdf.eps')

i=1
plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
for f in glob.iglob('./*.sizes'):
    dataset = f.replace('./', '').replace('.sizes', '')
    print("Plotting", 'fig4-'+str(i)+'-'+dataset+'-anonymity-cdf.eps')
    createFigDatasetAnonymityCDF(i, f)
    i += 1
