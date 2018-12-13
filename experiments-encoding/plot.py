#!/usr/bin/python3
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import sys
from utils import *

# colors and constants
colors = ['#0000FF', '#FF0000', '#800080', '#1E90FF', '#8A2BE2', '#FFA500', '#00FF00', '#F0F0F0']
fillcolors = [c + "AA" for c in colors]
markers = ['D', 'x', 'o', 'd']
linestyles = ['--', ':', '-', '-.']
patterns = ['', '.', '//']
mpl.rcParams['text.latex.preamble'] = [r'\usepackage{sansmath}', r'\sansmath']
mpl.rcParams['text.usetex'] = True
mpl.rcParams.update({'font.size': 16})


def plotHeaderSize():

    header_sizes = readAndProcessTwoLevels('header_sizes.json')

    labels = {}
    labels['purb-flat'] = 'PURBs (no GHT)'
    labels['purb'] = 'PURBs'
    i = 0
    for header_sizes_type in header_sizes:
        data = header_sizes[header_sizes_type]

        v = groupByKeyAndGetStats(data, key="nRecipients")

        Xs = [x for x in v]
        Ys = [v[x]['mean2'] for x in v]
        Yerr = [v[x]['err2'] for x in v]

        plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[i], label=labels[header_sizes_type], marker=markers[i], linestyle=linestyles[i],capsize=2)
        i += 1

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.legend()
    plt.xscale('log')
    #plt.yscale('log')
    plt.ylabel('Header Size [B]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()


def plotHeaderCompactness():

    header_sizes = readAndProcess('compactness.json')

    grouped_by_suite = groupByKey(header_sizes, "nSuites")

    suite_counter = 0
    for nsuite in grouped_by_suite:
        data2 = grouped_by_suite[nsuite]
        v = groupByKeyAndGetStats(data2, key="nRecipients")

        Xs = [x for x in v]
        Ys = [100 * (1 - v[x]['mean2']) for x in v]
        Yerr = [100 * v[x]['err2'] for x in v]

        plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[suite_counter], label=str(nsuite)+" Suites", marker=markers[suite_counter], linestyle=linestyles[suite_counter],capsize=2)
        suite_counter += 1


    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.legend()
    plt.xscale('log')
    plt.ylabel('Percentage of useful bits, \\%')
    plt.xlabel('Number of Recipients')
    axes = plt.gca()
    axes.set_ylim([0,105])
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()


def plotDecodeTime():
    decode = readAndProcessTwoLevels('decode.json')

    i = 0
    for decode_type in decode:
        data = decode[decode_type]

        v = groupByKeyAndGetStats(data, key="totalNRecipients")

        Xs = [x for x in v]
        Ys = [v[x]['mean2'] for x in v]
        Yerr = [v[x]['err2'] for x in v]

        plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[i], label=decode_type, marker=markers[i], linestyle=linestyles[i],capsize=2)
        i += 1

        
    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)

    plt.legend()
    plt.ylabel('Decoding time [ms]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.xscale('log')
    plt.yscale('log')
    plt.show()

def plotEncodingTime():
    encode = readAndProcessTwoLevels('encode.json')

    labels = {}
    labels['pgp'] = 'PGP'
    labels['pgp-hidden'] = 'PGP Hidden'
    labels['purb-flat'] = 'PURBs (no GHT)'
    labels['purb'] = 'PURBs'

    i = 0
    for encode_type in encode:
        data = encode[encode_type]

        # take only the data for 3 suites
        data_filtered = []
        for row in data:
            if row['nSuites'] == 3:
                data_filtered.append(row)

        v = groupByKeyAndGetStats(data_filtered, key="nRecipients")
        
        Xs = [x for x in v]
        Ys = [v[x]['mean2'] for x in v]
        Yerr = [v[x]['err2'] for x in v]
        plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[i], label=labels[encode_type], marker=markers[i], linestyle=linestyles[i],capsize=2)
        i += 1

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)

    plt.legend()
    plt.xscale('log')
    plt.yscale('log')
    plt.ylabel('CPU time [ms]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()

def plotEncodingPrecise():
    encode = readAndProcessTwoLevels('encode_precise.json')

    labels = {}
    labels['cs-ep-values'] = 'EP+CS Creation'
    labels['placement'] = 'Placement'
    labels['asym-crypto'] = 'KeyGen'
    labels['kdfs'] = 'SharedSecrets'
    width = 0.8

    #merge "payload", "CS-place", "" into "others"

    # compute those values to display the graph properly
    nRecipients = []
    nSuites = []
    for row in encode['asym-crypto']:
        if row['nRecipients'] not in nRecipients:
            nRecipients.append(row['nRecipients'])
        if row['nSuites'] not in nSuites:
            nSuites.append(row['nSuites'])

    # sets where each colum start Y-wise (stacked bar)
    lastValues = [0 for x in range(0,(len(nSuites)+1) * len(nRecipients))]

    order = ['cs-ep-values', 'placement', 'asym-crypto', 'kdfs']

    # start plotting loop
    data_type_counter = 0
    for encode_type in order:
        if encode_type not in encode:
            print("Skipping", encode_type, "not found in data")
            continue

        data = encode[encode_type]

        grouped_by_suite = groupByKey(data, "nSuites")

        suite_counter = 0
        for nsuite in grouped_by_suite:
            data2 = grouped_by_suite[nsuite]
            data3 = groupByKeyAndGetStats(data2, key="nRecipients")

            Xs = [x for x in data3]
            pos = [((len(nSuites) + 1) * x) + suite_counter for x in np.arange(len(data3))]
            Ys = [data3[x]['mean2'] for x in data3]
            Yerr = [data3[x]['err2'] for x in data3]

            # do not display if we have more suite than recipients
            i = 0
            while i < len(Xs):
                if Xs[i] < nsuite:
                    Ys[i] = 0
                i += 1

            bottoms=[]
            for p in pos:
                bottoms.append(lastValues[p])

            plt.bar(pos, Ys, bottom=bottoms, width=width, color=fillcolors[data_type_counter], edgecolor='black', label='', hatch=patterns[suite_counter])

            i = 0
            while i < len(Ys):
                lastValues[pos[i]] += Ys[i]
                i += 1

            suite_counter += 1

        data_type_counter += 1

    ticks = []
    ticks_positions = []
    i = 0
    while i<len(nRecipients):
        j = 0
        while j<len(nSuites):
            if len(ticks) == 0 or ticks[-1] != nRecipients[i]:
                ticks_positions.append((i * len(nSuites))+ j + i)
                ticks.append(nRecipients[i])
            j += 1
        i += 1
    ticks_positions = [x + 1 for x in ticks_positions]

    plt.xticks(ticks_positions, ticks)
    plt.ylabel('CPU time [ms]')
    plt.xlabel('Number of Recipients')
    plt.yscale('log')
    plt.grid(True, which="major", axis='y')

    legends = []
    i = 0
    for encode_type in order:
        data_serie = mpatches.Patch(facecolor=fillcolors[i], edgecolor='black', label=labels[encode_type])
        legends.append(data_serie)
        i += 1

    i = 0
    while i < len(nSuites):
        l = str(nSuites[i]) + ' suite'
        if nSuites[i] != 1:
            l+='s'
        data_serie = mpatches.Patch(facecolor='white', edgecolor='black', hatch=patterns[i], label=l)
        legends.append(data_serie)
        i += 1

    plt.legend(handles=legends, ncol=2, fontsize=13,labelspacing=0.2, columnspacing=1)

    plt.show()

if len(sys.argv) == 1:
    print("Usage: ./plot.py e|d|h|c|p, for Encode,Decode,HeaderSize,Compactness,encode Precise(stacked bars)")
else:
    if sys.argv[1] == 'e':
        plotEncodingTime()
    if sys.argv[1] == 'h':
        plotHeaderSize()
    if sys.argv[1] == 'd':
        plotDecodeTime()
    if sys.argv[1] == 'p':
        plotEncodingPrecise()
    if sys.argv[1] == 'c':
        plotHeaderCompactness()
