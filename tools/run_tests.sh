#!/bin/bash


pycodestyle pywally/ --max-line-length=140
python3 -m unittest discover -v
