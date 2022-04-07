import os
import json
import pickle
import sys
import pprint
pp = pprint.PrettyPrinter(indent=4)

from collections import Counter, OrderedDict
from statistics import mean, median, stdev
from typing import List, Dict, Tuple
from os.path import isdir, abspath, join, basename, exists, isfile

from classes import *


# use this function to get the features
def extract_features(report: DynAnal):
    out = list()
    for event in report.orderedEvents:
        t = event['Type']
        if t.startswith('BE'):
            category = event['Cat']
            symbol = event['Sym']
            arg = None
            if t.endswith('wA'):
                arg = event['Arg']
                if arg is not None:
                    if arg.startswith('\\??'):
                        arg = arg[4:]
                    elif arg.startswith('\\Dev'):
                        arg = arg.replace('\\Device\\HarddiskVolume2', 'C:')
                    out.append(f'{category}|{arg}')
            print(category, symbol, arg)  # <- behaviour features
        elif t == 'EVA':
            category = event['Cat']
            title = event['Title']
            print(category, title)  # <- evasive features
    return out

def is_empty(file_path: str) -> bool:
    try:
        return os.path.getsize(file_path) <= 0
    except OSError:
        return False


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {basename(__file__)} PICKLES_FOLDER')
    pickles_folder = sys.argv[1]
    assert isdir(pickles_folder)


    files = os.listdir(pickles_folder)
    print(f'Found #{len(files)} files')
    i = 0
    for filename in files:
        if filename.endswith('.pickle'):
            print(i, filename)
            i += 1
            if i == 42:
                break
            sha256 = filename[:-7]
            assert len(sha256) == 64
            fpath = join(pickles_folder, filename)
            assert not is_empty(fpath)
            try:
                with open(fpath, "rb") as fp:
                    da: DynAnal = pickle.load(fp)
                    pp.print(extract_features(da))
            except:
                pass