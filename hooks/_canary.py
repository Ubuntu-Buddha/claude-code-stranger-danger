"""The rules canary's shared pieces: the placeholder line, the word list,
filling the placeholder in, and the doctor's check of a stated word.

The canary only shows that a session loaded the rules, so the word needn't be
secret, only unlikely to come up by chance, and no session may learn it any
other way. Used by the canary_fill hook, setup's apply.py and the doctor.

Standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import string
from typing import Optional

PLACEHOLDER = "<your-canary-word>"
LINE = "Rules canary: " + PLACEHOLDER
# A word, a digit and a letter: 16,640 choices.
WORDS = (
    "alder", "amaranth", "anise", "arnica", "aster", "azolla", "balsa", "basalt",
    "betony", "borage", "bryony", "burdock", "calamus", "campion", "catkin", "chervil",
    "cinnabar", "cowslip", "cresset", "dittany", "dogbane", "feldspar", "fennel", "foxglove",
    "galena", "garnet", "gentian", "glasswort", "hawkweed", "henbit", "hornwort", "hyssop",
    "jasper", "juniper", "kelpie", "lichen", "loosestrife", "lovage", "madder", "marjoram",
    "meadowsweet", "mullein", "nettle", "obsidian", "orpine", "oxlip", "pennyroyal", "quartzite",
    "ramsons", "rowan", "rue", "samphire", "sorrel", "spurge", "tansy", "teasel",
    "toadflax", "tormentil", "vervain", "vetch", "woad", "wormwood", "yarrow", "zircon",
)
# What the doctor's check takes on its command line: nothing a shell treats
# specially, so the skill can pass it in single quotes.
CHECKABLE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_WORD = re.compile(r"Rules canary:\s*(\S+)")


def make(choice=secrets.choice) -> str:
    """A canary word such as "tansy-4k"."""
    return f"{choice(WORDS)}-{choice(string.digits)}{choice(string.ascii_lowercase)}"


def fill(text: str, word: str) -> Optional[str]:
    """`text` with the placeholder line filled in, or None if it has none. Only
    a line that is exactly the placeholder line, once stripped, counts, so an
    example quoted with `>` or backticks stays as it is. An exact line inside a
    fenced block counts too."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.strip() == LINE:
            lines[i] = line.replace(PLACEHOLDER, word, 1)
            return "\n".join(lines)
    return None


def word_in(text: str) -> Optional[str]:
    """The rules file's canary word, or None while it's unset. A line that
    starts with "Rules canary:", once stripped, wins over a mention inside
    other text, so a quoted example above the real line doesn't hide it."""
    lines = [line.strip() for line in text.split("\n")]
    m = next((_WORD.match(line) for line in lines if _WORD.match(line)), None) \
        or _WORD.search(text)
    word = m.group(1).rstrip(".") if m else ""
    if not word or word == PLACEHOLDER or word.startswith("<"):
        return None
    return word


def matches(stated: str, text: str) -> Optional[bool]:
    """Whether `stated` is the rules file's word; None while the file has none.
    It compares hashes in constant time, so nothing about the word shows."""
    word = word_in(text)
    if word is None:
        return None
    return hmac.compare_digest(hashlib.sha256(stated.encode("utf-8")).digest(),
                               hashlib.sha256(word.encode("utf-8")).digest())
