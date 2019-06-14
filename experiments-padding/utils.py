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
              'legend.loc': 'upper left',
              'lines.markersize': 9,
              'xtick.labelsize': 18,
              'ytick.labelsize': 18,
              'text.usetex': True,
              # 'figure.figsize': [fig_width,fig_height],
              'font.family': 'serif'
              }
    mpl.rcParams.update(params)
    
prepare_for_latex()