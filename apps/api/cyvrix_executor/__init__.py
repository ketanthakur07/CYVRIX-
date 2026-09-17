"""CYVRIX V3.4 — in-sandbox executor.

Stdlib-only package that runs INSIDE the ephemeral sandbox container.
It is the only code that touches workspace files, it is a CLOSED-WORLD
interpreter (unknown operation types deny), and it performs no network
I/O and no subprocess launches.
"""
