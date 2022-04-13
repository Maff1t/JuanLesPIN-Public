from typing import List, Dict, Optional, Set
from collections import defaultdict
import operator


class DynAnal:
    sha256: str
    pidToEvents: Dict[int, List[Dict]]
    pidToHoneypotEvents: Dict[int, List[Dict]]
    orderedEvents: List[Dict]
    evasiveBehaviour: Optional[Dict[str, Set[str]]]

    def __init__(self, sha256: str):
        self.sha256 = sha256
        self.pidToEvents = dict()
        self.pidToHoneypotEvents = dict()
        self.orderedEvents = list()
        self.evasiveBehaviour = None

    def sort_events(self):
        self.orderedEvents.sort(key=operator.itemgetter('Time'))

    def get_evasive_behaviour(self) -> Dict:
        if self.evasiveBehaviour is not None:
            return self.evasiveBehaviour
        self.evasiveBehaviour = defaultdict(set)
        for e in self.orderedEvents:
            if e['Type'] != 'EVA':
                continue
            self.evasiveBehaviour[e['Cat']].add(e['Title'])
        return self.evasiveBehaviour

    def evasion_detected(self) -> bool:
        return len(self.get_evasive_behaviour()) >= 1

    def injection_detected(self) -> bool:
        for pid, events in self.pidToHoneypotEvents.items():
            for e in events:
                if e['Type'] != 'INF':
                    return True
        return False

    def is_empty(self) -> bool:
        for event in self.orderedEvents:
            if event['Type'].startswith('BE'):
                return False
        return True

    def __str__(self):
        return f'sha256={self.sha256}, ' \
               f'nof_processes={len(self.pidToEvents)}, ' \
               f'nof_events={len(self.orderedEvents)}, ' \
               f'injection?{self.injection_detected()}, '\
               f'evasion?{self.evasion_detected()}'
