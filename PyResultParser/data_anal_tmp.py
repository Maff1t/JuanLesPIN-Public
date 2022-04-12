import os
import json
import pickle
import sys
from pprint import pprint
from pathlib import PureWindowsPath
from collections import Counter, OrderedDict
from statistics import mean, median, stdev
from typing import List, Dict, Tuple
from os.path import isdir, abspath, join, basename, exists, isfile

from classes import *


def extract_features(report: DynAnal) -> List:
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
                    arg = arg.lower()
                    arg = arg.replace('guannapenna', 'slasti')
                    if category in ['FILESYSTEM', 'PROCESS']:
                        try:
                            pwp = PureWindowsPath(arg)
                            arg = str(pwp).replace(pwp.stem, '')  # remove filename  but keep extension
                        except:
                            pass
                    elif category == 'NETWORK':
                        if ':' in arg:
                            arg = arg.split(':')[1]
                    elif category == 'MUTEX':
                        arg = ''  # mutex argument is useless
                    elif category == 'REGISTRY':
                        pass
                    elif category == 'SERVICE':
                        if 'name=' in arg:
                            arg = arg.split('=')[1]
                        else:
                            arg = ''
                        print(f'{category}|{symbol}|{arg}')
                    else:
                        print(f'{category}|{symbol}|{arg}')
                    arg = arg.replace(' ', '')
            if arg is None or arg == '':
                feat = f'{symbol}'
            else:
                feat = f'{symbol}|{arg}'
            out.append(feat)
        elif t == 'EVA':
            category = event['Cat']
            title = event['Title']
            #print(category, title)  # <- evasive features
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
            #print(i, filename)
            i += 1
            sha256 = filename[:-7]
            assert len(sha256) == 64
            fpath = join(pickles_folder, filename)
            assert not is_empty(fpath)
            with open(fpath, "rb") as fp:
                da: DynAnal = pickle.load(fp)
                features_list: List = extract_features(da)
                for feat in features_list:
                    api_name = None
                    arg = None
                    if '|' in feat:
                        spt = feat.split('|')
                        api_name = spt[0]
                        arg = spt[1]
                    else:
                        api_name = feat
                    print(api_name, arg)  # <- here you go!
