#!/usr/bin/python3
import json
from math import sqrt
import numpy as np
import matplotlib as mpl


def prepare_for_latex():
    # Setting parameters for Latex
    fig_width = 3.39
    golden_mean = (sqrt(5)-1.0)/2.0    # Aesthetic ratio
    fig_height = fig_width*golden_mean # height in inches
    MAX_HEIGHT_INCHES = 8.0
    if fig_height > MAX_HEIGHT_INCHES:
        print("WARNING: fig_height too large:" + fig_height +
              "so will reduce to" + MAX_HEIGHT_INCHES + "inches.")
        fig_height = MAX_HEIGHT_INCHES

    params = {'backend': 'ps',
              'text.latex.preamble': [r'\usepackage{gensymb}', r'\usepackage{sansmath}', r'\sansmath'],
              'axes.labelsize': 18, # fontsize for x and y labels (was 10)
              'axes.titlesize': 18,
              'font.size': 18, # was 10
              'legend.fontsize': 15, # was 10
              # 'legend.loc': 'upper left',
              'lines.markersize': 9,
              'xtick.labelsize': 18,
              'ytick.labelsize': 18,
              'text.usetex': True,
              # 'figure.figsize': [fig_width,fig_height],
              'font.family': 'serif'
              }
    mpl.rcParams.update(params)


def readAndProcess(file):
    data = []
    with open(file) as f:
        data = json.load(f)
    return process(data)


def readAndProcessTwoLevels(file):
    data = []
    with open(file) as f:
        data = json.load(f)

    data2 = {}
    for data_type in data:
        data2[data_type] = process(data[data_type])

    return data2


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


def groupByKey(data, key):
    grouped_per_key = {}
    for line in data:
        n_recipients = line[key]
        if n_recipients not in grouped_per_key:
            grouped_per_key[n_recipients] = []
        grouped_per_key[n_recipients].append(line)

    return grouped_per_key


def groupByKeyAndGetStats(data, key):
    grouped_per_key = groupByKey(data, key)

    results = {}
    for group in grouped_per_key:
        values = [x['value'] for x in grouped_per_key[group]]
        results[group] = stats(values)
    return results


def stats(data):
    s = dict()
    s['mean'] = mean(data)
    s['err'] = percentile(data)
    s['min'] = min(data)
    s['max'] = max(data)
    s['count'] = len(data)
    a = median_and_deviation(data)
    s['mean2'] = a[0]
    s['err2'] = a[1]
    return s


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


def median_and_deviation(elems):
    a = np.array(elems)
    a = a.astype(np.float)
    dev = a.std()
    devs = enumerate([abs(elem - dev) for elem in a])
    outlier = max(devs, key=lambda k: k[1])
    a = np.delete(a, outlier[0])
    dev = a.std()
    # mean = a.mean()
    median = np.median(a)
    return median, dev