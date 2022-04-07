import os
import json
import pickle
import sys
from collections import Counter, OrderedDict
from statistics import mean, median, stdev
from typing import List, Dict, Tuple
from os.path import isdir, abspath, join, basename, exists, isfile

from classes import *


# use this function to get the features
def extract_features(report: DynAnal):
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
            print(category, symbol, arg)  # <- behaviour features
        elif t == 'EVA':
            category = event['Cat']
            title = event['Title']
            print(category, title)  # <- evasive features


def get_perc_round(tot: int, part: int, round_n: int = 1) -> float:
    return round(part * 100 / tot, round_n)


def get_statistics(data: List, round_n: int = 2) -> Tuple:
    return min(data), max(data), median(data), round(mean(data), round_n), round(stdev(data), round_n)


def get_counter_perc(tot: int, data: List) -> Dict[str, float]:
    out = OrderedDict()
    for x, y in Counter(data).items():
        out[x] = get_perc_round(tot, y)
    return out


def is_empty(file_path: str) -> bool:
    try:
        return os.path.getsize(file_path) <= 0
    except OSError:
        return False


def write_flush(fp, s: str):
    fp.write(f'{s}\n')
    fp.flush()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {basename(__file__)} PICKLES_FOLDER')
    pickles_folder = sys.argv[1]
    assert exists(pickles_folder)

    if isfile(pickles_folder):
        with open(pickles_folder, "rb") as fp:
            da: DynAnal = pickle.load(fp)
            print(str(da))
            breakpoint()
        sys.exit()

    assert isdir(pickles_folder)
    tot_samples: int = 0
    empty_samples: int = 0
    empty_files: int = 0
    broken_pickle: int = 0
    evasive_samples: int = 0
    injection_samples: int = 0
    n_of_events: List = list()
    n_of_processes: List = list()
    n_of_evasive: Dict[str, List] = defaultdict(list)
    files = os.listdir(pickles_folder)
    print(f'Found #{len(files)} files')
    with open('empty.txtl', 'w') as fp_empty:
        for filename in files:
            if filename.endswith('.pickle'):
                sha256 = filename[:-7]
                assert len(sha256) == 64
                fpath = join(pickles_folder, filename)
                if is_empty(fpath):
                    empty_files += 1
                    write_flush(fp, sha256)
                    continue
                try:
                    with open(fpath, "rb") as fp:
                        da: DynAnal = pickle.load(fp)
                        #extract_features(da)  # for the ML guys, uncomment this call
                        tot_samples += 1
                        print(tot_samples)
                        n_of_processes.append(len(da.pidToEvents))
                        if da.is_empty():
                            empty_samples += 1
                            write_flush(fp_empty, 'E,'+sha256)
                        n_of_events.append(len(da.orderedEvents))
                        if da.evasion_detected():
                            evasive_samples += 1
                            for cat, titles in da.get_evasive_behaviour().items():
                                for t in titles:
                                    n_of_evasive[cat].append(t)
                        if da.injection_detected():
                            injection_samples += 1
                except Exception:
                    broken_pickle += 1
                    write_flush(fp_empty, 'B,' + sha256)
    print('tot_samples', tot_samples)
    print('broken_pickle', broken_pickle)
    print('empty_samples', get_perc_round(tot_samples, empty_samples))
    print('evasive_samples', get_perc_round(tot_samples, evasive_samples))
    print('injection_samples', get_perc_round(tot_samples, injection_samples))
    print('n_of_events', get_statistics(n_of_events))
    print('n_of_processes', get_statistics(n_of_processes))

    print('\nEvasive:')
    for k, v in n_of_evasive.items():
        print(k, get_counter_perc(evasive_samples, v))
