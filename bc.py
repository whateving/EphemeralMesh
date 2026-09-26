"""Compatibility entry point for the supported persistent chat client.

The old terminal client used the retired, ID-only protocol. The relay lives in main.py.
"""
import asyncio
from contextlib import suppress
import logging
from chat_client import main

if __name__ == '__main__':
    # Share one implementation so authentication and cryptography cannot diverge.
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    with suppress(KeyboardInterrupt):
        asyncio.run(main())
