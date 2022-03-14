import os
import json
import time
import pickle
import codecs
import sys

from typing import List, Dict
from multiprocessing import Pool, Value
from os.path import isdir, abspath, join, basename, exists

from classes import *


def group_by_sha256(folder: str) -> List[List[str]]:
    samples = {}
    for filename in os.listdir(folder):
        if filename.endswith('.json'):
            sha256 = filename.split(".")[0]
            if len(sha256) != 64:
                print('[!] error w/ filename:', filename)
                continue
            if sha256 not in samples:
                samples[sha256] = [abspath(join(folder, filename))]
            else:
                samples[sha256].append(abspath(join(folder, filename)))
    return list(samples.values())


def elaborate_file(reportFilesList: List[str], dstPath: str):
    sha256 = basename(reportFilesList[0]).split(".")[0]
    if len(sha256) != 64:
        print(f'[!] Wrong {sha256=} taken from: {reportFilesList[0]}')
        return
    dst_file = join(dstPath, sha256 + ".pickle")
    if exists(dst_file):
        return

    dynanal = DynAnal(sha256)
    for file_path in reportFilesList:
        with codecs.open(file_path, 'r', encoding='utf-8', errors="replace") as in_file:
            read = in_file.read()
            if not len(read):
                continue

            path_split = file_path[:-5].split('-')
            is_honey = 'honey' in file_path
            if is_honey:
                pid = int(path_split[2])
                dynanal.pidToHoneypotEvents[pid] = list()
            else:
                pid = int(path_split[1])
                dynanal.pidToEvents[pid] = list()

            i = 0
            for line in read.splitlines():
                i += 1
                try:
                    jl: Dict = json.loads(line.replace('\\', '\\\\'))
                    if not isinstance(jl, dict): continue
                    if 'Time' not in jl: continue
                    if is_honey:
                        dynanal.pidToHoneypotEvents[pid].append(jl)
                    else:
                        dynanal.pidToEvents[pid].append(jl)
                    dynanal.orderedEvents.append(jl)
                except Exception as e:
                    print(f'{file_path}@{str(i)} Ex=|{str(e)}| Line=|{line}|')
    dynanal.sort_events()
    with open(dst_file, "wb+") as f:
        pickle.dump(dynanal, f)


def elaborate_reports(src_folder: str, dst_folder: str, cores: int = 3):
    dst_folder = join(dst_folder, "pickles")
    if not exists(dst_folder):
        os.makedirs(dst_folder)
    print("Grouping json files by sha256")
    list_of_samples = group_by_sha256(src_folder)
    print(f"Elaborating {len(list_of_samples)} samples using {cores=}")
    start_time = time.time()
    with Pool(cores) as pool:
        pool.starmap(elaborate_file,
                     list(zip(list_of_samples, [dst_folder for _ in range(len(list_of_samples))])))
    print(f"> Elaborated {len(list_of_samples)} samples in "
          f"{round(time.time() - start_time, 1)} sec using {cores=}")


def debug_pickle(pickle_path: str):
    with (open(pickle_path, "rb")) as fp:
        p = pickle.load(fp)
        print(p)
        print(p.get_evasive_behaviour())
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {basename(__file__)} REPORTS_FOLDER DST_FOLDER')
    reports_folder = sys.argv[1]
    assert isdir(reports_folder)
    dst_folder = sys.argv[2]
    assert isdir(dst_folder)

    elaborate_reports(reports_folder, dst_folder)
