"""The six ZeroTrustVault attack scenarios, in demo order."""
from . import a1_idor, a2_stolen_creds, a3_mitm, a4_tamper, a5_replay, a6_insider

ATTACKS = [a1_idor, a2_stolen_creds, a3_mitm, a4_tamper, a5_replay, a6_insider]
BY_KEY = {m.NAME: m for m in ATTACKS}
# short keys: a1..a6
BY_SHORT = {m.NAME.split("_")[0]: m for m in ATTACKS}


def resolve(token: str):
    token = token.strip()
    if token in BY_KEY:
        return BY_KEY[token]
    if token in BY_SHORT:
        return BY_SHORT[token]
    raise KeyError(token)
