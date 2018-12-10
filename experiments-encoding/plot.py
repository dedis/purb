#!/usr/bin/python3
import json
from pprint import pprint
from math import sqrt
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import sys
from utils import *

color = ['#0000FF', '#FF0000', '#800080', '#1E90FF', '#8A2BE2', '#FFA500', '#00FF00', '#F0F0F0']
markers = ['D', 'x', 'o', 'd']
linestyles = ['--', ':', '-', '-.']
patterns = ['', '//', '.']

mpl.rcParams['text.latex.preamble'] = [r'\usepackage{sansmath}', r'\sansmath']
mpl.rcParams['text.usetex'] = True
mpl.rcParams.update({'font.size': 16})

def plotHeaderSize():
    header_sizes = readAndProcess('header_sizes.json')
    v = groupByKeyAndGetStats(header_sizes, key="nRecipients")

    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]
    Yerr = [v[x]['err2'] for x in v]

    plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[0], label='Header Size', marker=markers[0], linestyle=linestyle[0],capsize=2)

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.legend()
    plt.ylabel('Header Size [B]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()


def plotDecodeTime():
    decode = readAndProcess('decode.json')
    v = groupByKeyAndGetStats(decode, key="totalNRecipients")

    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]
    Yerr = [v[x]['err2'] for x in v]

    plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[0], label='PURB', marker=markers[0], linestyle=linestyle[0],capsize=2)

    decode = readAndProcess('decode_pgp.json')
    v = groupByKeyAndGetStats(decode, key="totalNRecipients")
    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]
    Yerr = [v[x]['err2'] for x in v]

    plt.errorbar(Xs, Ys, yerr=Yerr, color=colors[1], label='PGP', marker=markers[1], linestyle=linestyle[1],capsize=2)

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)

    plt.legend()
    plt.ylabel('Decoding time [ms]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()

def plotEncodingTime():
    encode = readAndProcess2('encode.json')

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

        plt.errorbar(Xs, Ys, yerr=Yerr, color=color[i], label=labels[encode_type], marker=markers[i], linestyle=linestyles[i],capsize=2)
        i += 1

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)

    plt.legend()
    plt.ylabel('Encoding time [ms]')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()

def plotEncodingPrecise():
    encode = readAndProcess2('encode_precise.json')

    labels = {}
    labels['pgp'] = 'PGP'
    labels['pgp-hidden'] = 'PGP Hidden'
    labels['purb-flat'] = 'PURBs (no GHT)'
    labels['purb'] = 'PURBs'
    width = 0.8

    nRecipients = []
    nSuites = []
    for row in encode['asym-crypto']:
        if row['nRecipients'] not in nRecipients:
            nRecipients.append(row['nRecipients'])
        if row['nSuites'] not in nSuites:
            nSuites.append(row['nSuites'])


    data_type_counter = 0
    for encode_type in encode:
        data = encode[encode_type]

        grouped_by_suite = groupByKey(data, "nSuites")

        suite_counter = 0
        for nsuite in grouped_by_suite:
            data2 = grouped_by_suite[nsuite]
            data3 = groupByKeyAndGetStats(data2, key="nRecipients")

            Xs = [((len(nRecipients) + 1) * x) + suite_counter for x in np.arange(len(data3))]
            Ys = [data3[x]['mean2'] for x in data3]
            Yerr = [data3[x]['err2'] for x in data3]

            plt.bar(Xs, Ys, width, color=color[data_type_counter], edgecolor='black', label='xxx', hatch=patterns[suite_counter])
            suite_counter += 1

        data_type_counter += 1

    ticks = []
    ticks_positions = []
    i = 0
    while i<len(nRecipients):
        j = 0
        while j<len(nSuites):
            ticks_positions.append((i * len(nRecipients))+ j + i)
            ticks.append(nRecipients[i])
            j += 1
        i += 1

    print(ticks_positions)
    print(ticks)

    plt.xticks(ticks_positions, ticks)
    plt.ylabel('CPU time, ms')
    plt.xlabel('Number of Recipients')
    plt.yscale('log')
    plt.grid(True, which="major", axis='y')

    legends = []
    i = 0
    while i < len(nSuites):
        dataserie = mpatches.Patch(facecolor='white', edgecolor='black', hatch=patterns[i], label=str(nSuites[i]) + ' suite')
        legends.append(dataserie)
        i += 1

    i = 0
    for encode_type in encode:
        dataserie = mpatches.Patch(facecolor=color[i], edgecolor='black', label=encode_type)
        legends.append(dataserie)
        i += 1

    plt.legend(handles=legends, ncol=2, fontsize=13,labelspacing=0.2, columnspacing=1)

    plt.show()

plotEncodingPrecise()