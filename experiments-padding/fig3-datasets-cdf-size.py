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

def parseFile(file):
    Ls = []
    with open(file, "r") as f:
        for line in f:
            L = int(line.strip())
            if L == 0 or L == 1:
                continue
            Ls.append(L)
    return Ls

datasets = {}
for f in glob.iglob('./*.sizes'):
    #print("Parsing", f)
    datasets[f] = np.sort(parseFile(f))

legends = []
for d in datasets:
    data = datasets[d]
    p = 100. * np.arange(len(data)) / (len(data) - 1)

    prettyName = d.replace('./', '').replace('.sizes', '')
    plt.plot(data, p, color=datasets_color[prettyName], linestyle=datasets_style[prettyName], linewidth=curve_width)
    legends.append(prettyName)

#plt.title('CDF of object sizes in the datasets')
plt.title('')

plt.ylabel('Percentile')
plt.xlabel('Size of objects [bits]')
plt.legend(legends, loc='upper left')

plt.xscale('log')
#plt.yscale('log')

plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
plt.tight_layout()
plt.savefig('fig3-datasets-cdf-size.eps')
