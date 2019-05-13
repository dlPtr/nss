#!/usr/bin/python3

import signal as sn

def _delay(n):
    for t in range(n * 0xfff * 0xfff):
        pass

def delay(n):
    for i in range(n):
        _delay(3)
        print("<------python------>")

def foo(n1, n2):
    print("--%s--: python not handle over." % ("hello.py"))
    exit()

sn.signal(sn.SIGINT, foo)

delay(5)

print("--hello.py--: Analyze over!\n")