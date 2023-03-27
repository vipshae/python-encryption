#!/bin/sh

python3 -m venv env
source env/bin/activate

pip3 install cryptography

python3 asymm-encryption.py