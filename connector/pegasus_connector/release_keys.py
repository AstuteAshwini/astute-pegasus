"""Public keys of the Astute release key(s). The connector installs an update only if it is signed by one of these.

The private key never goes near the control plane: it stays with whoever builds releases (scripts/connector_release.py
creates it and adds its public key here). Because these keys are part of the connector's own code, the control plane
can hand out releases but can't make one, so a compromised control plane still can't run new code on a client's
machine. While this list is empty, the connector refuses every update.

To change keys, add the new public key here, release a version carrying both keys, and only then start signing with
the new key.
"""
RELEASE_KEYS = [
]
