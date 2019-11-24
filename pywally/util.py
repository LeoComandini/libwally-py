import wallycore as wally


h2b = wally.hex_to_bytes
b2h = wally.hex_from_bytes


def h2b_rev(h):
    return h2b(h)[::-1]


def b2h_rev(b):
    return b2h(b[::-1])


def harden(n):
    return 0x80000000 | n
