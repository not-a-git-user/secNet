"""Public key-exchange capability list.

The old file contained standalone experimental primitives that were never
used by the client or server.  The negotiated implementations now live in
``handshake.py`` so that key exchange, transcript verification, and session
key derivation cannot drift apart.  These exports keep capability discovery
convenient for external callers.
"""

from handshake import KEY_EXCHANGES, available_key_exchanges, ml_kem_available


SUPPORTED_KEY_EXCHANGES = KEY_EXCHANGES


__all__ = [
    "KEY_EXCHANGES",
    "SUPPORTED_KEY_EXCHANGES",
    "available_key_exchanges",
    "ml_kem_available",
]
