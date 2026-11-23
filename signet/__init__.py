"""signet: the keyholder. A separate signer program, a signed key registry and a tamper-evident signature log.

The programs that need signatures (zeta, beta, delta, HERALD, the HUMANITY issuer) never hold a key. They hand
signet bytes and a purpose over a local socket (`signet.client`), and signet signs with the one key that purpose
owns, if the bytes start with that purpose's label and the caller is allowed. Checkers read the signed registry
(`signet.registry`) and check with `signet.verify`. See README.md for what this does and does not protect.
"""

__version__ = "0.1.0"
