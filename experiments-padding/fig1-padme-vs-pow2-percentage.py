#!/bin/python3

import math
from math import ceil
import matplotlib.pyplot as plt
from colors import *
from padme import *
import matplotlib

matplotlib.rcParams.update({'font.size': font_size})

def getNextPowerOfTwo(x):
    exp = math.ceil(math.log(x,2))
    return math.pow(2,exp)


xVals = []
padMeEffectiveSizes = []
pow2EffectiveSizes = []

L = 10
end = 1000 * 1000

while L < end:
    a = 100 * float(getPadme(L) - L) / L
    b = 100 * float(getNextPowerOfTwo(L) - L) / L

    #print(L, a, b)

    xVals.append(L)
    padMeEffectiveSizes.append(a)
    pow2EffectiveSizes.append(b)

    L += 10

#plot data

plt.plot(xVals, padMeEffectiveSizes, color=padme_color, linestyle=padme_style, linewidth=curve_width, label='PadMé')
plt.plot(xVals, pow2EffectiveSizes, color=nextpow2_color, linestyle=nextpow2_style, linewidth=curve_width, label='Next power of 2')
plt.legend(loc='upper right')

plt.xscale('log')
#plt.yscale('log')

plt.xlim([1000, end])

plt.title('')
plt.xlabel('original size L [b]')
plt.ylabel('padding overhead [%]')

plt.tight_layout()
plt.savefig('fig1-padme-vs-pow2-percentage.eps')