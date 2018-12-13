#!/usr/bin/python3
import json
from math import sqrt
import numpy as np


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
    a =mean_and_deviation(data)
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