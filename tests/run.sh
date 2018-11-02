#!/bin/sh

TEST=`find -name "feature_erase.py"`
CONFIG=`find -name "config.ini"`

BITCOIND=`which bitcoind` BITCOINCLI=`which bitcoin-cli` $TEST --configfile=$CONFIG
