#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import sys


def main():
    """TODO: Docstring for main.
    :returns: TODO

    """
    with open(sys.argv[1]) as config_fp:
        decoded = json.load(config_fp)
    print(decoded)


if __name__ == "__main__":
    main()
