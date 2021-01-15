# libwally-py
Pythonic wrapper of [libwally](https://github.com/ElementsProject/libwally-core).

Libwally is written in C and exposes (among others) Python bindings, however
the exposed Python interface almost matches the C one. It has the advantage of
being easier to maintain while preserving all features, but has the negative
side of being rather complicated to use from Python. This wrapper aims to
provide Python developers with a simpler interface to a subset of libwally
features.

**WARNING**: libwally-py is in planning status, expect breaking changes and
bugs.

## Setup

Create and activate a virtualenv (optional):

    virtualenv -p python3 venv
    source venv/bin/activate

Install libwally-py:

    pip install .

## Tests

    ./tools/run_tests.sh

## LICENSE

[MIT](LICENSE)
