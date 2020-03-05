#!/usr/bin/env python3

import subprocess
import sys


def powerset(input):
    if len(input) == 0:
        return [[]]

    pivot = input[0]

    subset = powerset(input[1:])
    with_pivot = subset.copy()
    for i, set in enumerate(with_pivot):
        with_pivot[i] = [pivot] + set

    return subset + with_pivot


def check(toolchain, features):
    for subset in powerset(features):
        feature_str = ",".join(subset)
        print("$ cargo +" + toolchain + " check --no-default-features --features " + feature_str)

        status = subprocess.run([
            "cargo", "+" + toolchain, "check", "--no-default-features", "--features", feature_str
        ])
        if status.returncode != 0:
            sys.exit(1)

        print("$ cargo +" + toolchain + " test --no-default-features --no-run --features " + feature_str)

        status = subprocess.run([
            "cargo", "+" + toolchain, "test", "--no-default-features", "--no-run", "--features", feature_str
        ])
        if status.returncode != 0:
            sys.exit(1)




features = [
    "rewriter",
    "updater",
    "add_rulesets",
    "potentially_applicable",
    "settings",
    "get_simple_rules_ending_with",
]

check("stable", features)
