#!/usr/bin/python3

import math
from math import floor 

def log(x):
    return math.log(x, 2)

def getPadme(L):
    L = int(L)
    U = int(floor(log(L)))
    V = int(floor(log(U))+1)
    lastBits = U-V

    bitMask = (2 ** lastBits - 1)

    if L & bitMask == 0:
        return L

    L += (1 << lastBits)
    L = ((L >> lastBits) << lastBits)

    return L
