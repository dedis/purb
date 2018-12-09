#!/usr/bin/python3
import json
from pprint import pprint
from math import sqrt
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import sys

colorbar = ['#EBEBEB', '#FFE5CC', '#CCE5FF']
# colorbar = ['#EBEBEB', "#c2c2ff", "#C5E1C5", "#fffaca", "#ffc2c2", "#9EFFE3"]
colorlog = ['#E2DC27', '#071784', '#077C0F', '#BC220A']
hatches = ['', '//', '.']

def arr_sum(data):
    acc = 0.0
    for x in data:
        acc += x
    return acc

def mean(data):
    return round(100*float(arr_sum(data))/len(data))/100

def percentile(data):
    if len(data) == 0:
        return 0;
    mean_value = mean(data)
    deviations = []

    for x in data:
        deviations.append((x-mean_value)**2)

    std = mean(deviations)
    sterr = sqrt(std)
    z_value_95 = 1.96
    margin_error = sterr * z_value_95
    return round(100*margin_error)/100

def mean_and_deviation(elems):
    a = np.array(elems)
    a = a.astype(np.float)
    dev = a.std()
    devs = enumerate([abs(elem - dev) for elem in a])
    outlier = max(devs, key=lambda k: k[1])
    a = np.delete(a, outlier[0])
    dev = a.std()
    mean = a.mean()
    return mean, dev

def stats(data):
    s = {}
    s['mean'] = mean(data)
    s['err'] = percentile(data)
    s['min'] = min(data)
    s['max'] = max(data)
    s['count'] = len(data)
    a =mean_and_deviation(data)
    s['mean2'] = a[0]
    s['err2'] = a[1]
    return s

def process(data):
    # remove non-data
    data2 = []
    for line in data:
        line2 = {}
        for key in line:
            if line[key] != "-1" and line[key] != -1:
                if key == "value":
                    line2[key] = float(line[key])
                else:
                    line2[key] = int(line[key])
        data2.append(line2)

    return data2


def readAndProcess(file):
    data = []
    with open(file) as f:
        data = json.load(f)
    return process(data)

def readAndProcess2(file):
    data = []
    with open(file) as f:
        data = json.load(f)

    data2 = {}
    for data_type in data:
        data2[data_type] = process(data[data_type])

    return data2

def groupByNSuites(data):
    grouped_per_suite = {}
    for line in data:
        n_suite = line['nSuites']
        if n_suite not in grouped_per_suite:
            grouped_per_suite[n_suite] = []
        grouped_per_suite[n_suite].append(line)

    return grouped_per_suite

def groupByNRecipientsAndGetStats(data):
    grouped_per_recipients = {}
    for line in data:
        n_recipients = line['nRecipients']
        if n_recipients not in grouped_per_recipients:
            grouped_per_recipients[n_recipients] = []
        grouped_per_recipients[n_recipients].append(line)

    results = {}
    for group in grouped_per_recipients:
        values = [x['value'] for x in grouped_per_recipients[group]]
        results[group] = stats(values)
    return results

# plotting settings
mpl.rcParams['text.latex.preamble'] = [r'\usepackage{sansmath}', r'\sansmath']
# mpl.rcParams['font.family'] = 'sans-serif'  # ... for regular text
mpl.rcParams['text.usetex'] = True
# mpl.rcParams['font.sans-serif'] = 'Computer Modern Sans serif'
mpl.rcParams.update({'font.size': 16})

def plotHeaderSize():
    header_sizes = readAndProcess('header_sizes.json')
    v = groupByNRecipientsAndGetStats(header_sizes)
    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]

    plt.plot(Xs, Ys, color='#0000FF', label='Header Size', marker='d')
    #plt.fill_between(Xs, Ys, facecolor='#FFFDCD')

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    #plt.xlim(1, 4000)
    plt.legend()
    plt.ylabel('Header Size, bytes')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()


def plotDecodeTime():
    decode = readAndProcess('decode.json')
    v = groupByNRecipientsAndGetStats(decode)
    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]

    plt.plot(Xs, Ys, color='#0000FF', label='PURB', marker='d')
    #plt.fill_between(Xs, Ys, facecolor='#FFFDCD')

    decode = readAndProcess('decode_pgp.json')
    v = groupByNRecipientsAndGetStats(decode)
    Xs = [x for x in v]
    Ys = [v[x]['mean2'] for x in v]

    plt.plot(Xs, Ys, color='#0000FF', label='PGP', marker='d')
    #plt.fill_between(Xs, Ys, facecolor='#FFFDCD')

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    #plt.xlim(1, 4000)
    plt.legend()
    plt.ylabel('Mean time to decode')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    plt.show()

# do the plotting

encode = readAndProcess2('encode.json')
for encode_type in encode:
    data = encode[encode_type]
    grouped_by_suite = groupByNSuites(data)
    grouped_by_suite_processed = {}
    for s in grouped_by_suite:
        data2 = grouped_by_suite[s]
        data3 = groupByNRecipientsAndGetStats(data2)
        grouped_by_suite_processed[s] = data3

plotDecodeTime()