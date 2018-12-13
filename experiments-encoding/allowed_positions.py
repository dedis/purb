#!/usr/bin/python3
import itertools
import sys
import copy

SUITES = dict()
SUITES['a'] = {'cornerstone_len': 64, 'entrypoint_len': 48}
SUITES['b'] = {'cornerstone_len': 32, 'entrypoint_len': 48}
SUITES['c'] = {'cornerstone_len': 64, 'entrypoint_len': 80}
SUITES['d'] = {'cornerstone_len': 32, 'entrypoint_len': 80}
SUITES['e'] = {'cornerstone_len': 64, 'entrypoint_len': 64}
SUITES['f'] = {'cornerstone_len': 32, 'entrypoint_len': 64}

# toy example

#SUITES = dict()
#SUITES['a'] = {'cornerstone_len': 1, 'entrypoint_len': 0}
#SUITES['b'] = {'cornerstone_len': 2, 'entrypoint_len': 0}
#SUITES['c'] = {'cornerstone_len': 1, 'entrypoint_len': 0}
#SUITES['d'] = {'cornerstone_len': 1, 'entrypoint_len': 0}

print("Suites:")
for s in SUITES:
    print(s, SUITES[s])

suites_allowed_positions = dict()
for suite_name in SUITES:
    suites_allowed_positions[suite_name] = []

limit = 1
nextFreeIndex = 0
for suite in SUITES:
    last_insert = 0
    while len(suites_allowed_positions[suite]) < limit - 1:
        suites_allowed_positions[suite].append(last_insert)
        last_insert += SUITES[suite]['cornerstone_len']

    # add the exlusive position
    suites_allowed_positions[suite].append(nextFreeIndex)
    nextFreeIndex += SUITES[suite]['cornerstone_len']
    limit += 1

    # backtrack, make sure the solution n-1 does not overlap with the exclusive solution
    if len(suites_allowed_positions[suite]) >= 2:
        l = len(suites_allowed_positions[suite])
        before_last = suites_allowed_positions[suite][l-2]
        last = suites_allowed_positions[suite][l-1]

        if before_last + SUITES[suite]['cornerstone_len'] >= last:
            del suites_allowed_positions[suite][l-2]

print()
print("Per suite:")


for suite in suites_allowed_positions:
    positions = sorted(suites_allowed_positions[suite])
    print(suite, ":", positions)


print()
print("Per position:")

# format per position
max_value = 0

for suite_name in suites_allowed_positions:
    for suite_pos in suites_allowed_positions[suite_name]:
        if max_value < suite_pos:
            max_value = suite_pos

for pos in range(0, max_value+1):
    suites_at_pos = []

    for suite_name in suites_allowed_positions:
        for suite_pos in suites_allowed_positions[suite_name]:
            if suite_pos == pos and suite not in suites_at_pos:
                suites_at_pos.append(suite_name)

    if len(suites_at_pos) > 0:
        print(pos, ":", suites_at_pos)


print()
print("Sanity check, trying to place them all")

def place(allowed_positions, suites_to_place, solution = dict()):
    if len(suites_to_place) == 0:
        return solution

    suite_to_place = suites_to_place[0]

    #print("suite to place", suite_to_place)

    possible_positions_for_this_suite = sorted(allowed_positions[suite_to_place])
    #print("possible positions for this suite", possible_positions_for_this_suite)

    # for this suite, try all possible positions
    for pos in possible_positions_for_this_suite:

        start = pos
        end = start + SUITES[suite_to_place]['cornerstone_len']

        # we decide that we place it here
        #print("placing", suite_to_place, start, end)
        solution[suite_to_place] = [start, end]

        # now, this forbids other suites to overlap
        filtered_positions = copy.deepcopy(allowed_positions)
        for pos_to_ban in possible_positions_for_this_suite:
            for other_suite in allowed_positions:
                start = pos_to_ban
                end = start + SUITES[suite_to_place]['cornerstone_len']
                filtered_positions[other_suite] = [pos2 for pos2 in filtered_positions[other_suite] if pos2 >= end or pos2 + SUITES[other_suite]['cornerstone_len'] <= start]

        to_place = [suite for suite in suites_to_place if suite != suite_to_place]

        #print("to_place", to_place)
        #print("filtered_positions", filtered_positions)

        res = place(filtered_positions, to_place, solution)
        
        if res is not None:
            return res

    return None

for n_suites in range(1, len(SUITES)):
    for subset in itertools.combinations(SUITES, n_suites+1):
        solution = place(suites_allowed_positions, subset, dict())
        if solution is None:
            print("Could not find a mapping for", subset)
            sys.exit(1)
        else:
            print("Placing", subset, "solution is", solution)

print("OK")