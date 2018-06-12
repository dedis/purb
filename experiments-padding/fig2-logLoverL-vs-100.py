#!/bin/python3

import math
from math import ceil
import matplotlib.pyplot as plt
from colors import *
from padme import *
import matplotlib

matplotlib.rcParams.update({'font.size': font_size})

xVals = []
yValsPadme = []
yValsPadmeEstimation = []
yValsNextPowOf2 = []

L = 4
end = 1000 * 1000
m = 0
mVal = 0
while L < end:

    xVals.append(L)
    yValsPadme.append(100 * 1.00 / (2.00 * log(L)))
    if log(L)/L > mVal:
        m = L
        mVal = log(L)/L
    yValsPadmeEstimation.append(100. / math.sqrt(L))

    B = math.pow(2, math.ceil(math.log(L, 2)))
    yValsNextPowOf2.append(100. * float(B-L)/L) # max overhead of nextpow2 is always 100

    L += 1

# yValsNextPowOf2 oscillate; it's not the max overhead, it's the overhead. Do a mobile average to show the max

xValsNextPowOf2Max = []
yValsNextPowOf2Max = []
mobileAveragePoints =  2
i = 0
while i < len(yValsNextPowOf2):
    end = min(i+mobileAveragePoints, len(yValsNextPowOf2))
    data = yValsNextPowOf2[i:end]

    # find the max and its pos
    currMax = -1
    currMaxPos = -1
    j = 0
    while j<len(data):
        if data[j]>currMax:
            currMax = data[j]
            currMaxPos = j
        j += 1

    xValsNextPowOf2Max.append(4 + i+currMaxPos)
    yValsNextPowOf2Max.append(currMax)
    i += mobileAveragePoints
    mobileAveragePoints = math.ceil(math.pow(mobileAveragePoints,2)) # the scale is log, hence we distribute the points like this too

#plot data

plt.plot(xValsNextPowOf2Max, yValsNextPowOf2Max, color=nextpow2_color, linestyle=nextpow2_style, linewidth=curve_width, label='Next power of 2 - O(100%)')
plt.plot(xVals, yValsPadme, color=padme_color, linestyle=padme_style, linewidth=curve_width, label='Padmé overhead estimate - 1/(2*log L)')
#plt.plot(xVals, yValsPadmeEstimation, color=padme2_color, linestyle=padme2_style, linewidth=curve_width, label='Padmé approx - 1/sqrt(L)')
plt.legend(loc='center right')

plt.xscale('log')
#plt.yscale('log')

plt.xlabel('L [b]')
plt.ylabel('Overhead [%]')

plt.grid(color=grid_color, linestyle=grid_style, linewidth=grid_width)
plt.title('')
plt.tight_layout()
plt.savefig('fig2-logLoverL-vs-100.eps')