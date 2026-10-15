"""Domain helpers: registrable domains, IDN decoding, lookalike detection."""

import ipaddress
import re
from functools import lru_cache

import tldextract

from app.data.brands import BRANDS

# Use the Public Suffix List snapshot bundled with the package:
# no network calls and no cache files at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Characters attackers swap for look-alike letters (digits, Cyrillic, Greek).
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v",
})
_MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
# Words glued to a brand name in phishing domains (securepaypallogin.com).
_PHISHING_WORDS = (
    "secure", "login", "logon", "signin", "verify", "verification", "account", "update",
    "support", "service", "billing", "auth", "alert", "unlock", "recover", "confirm", "wallet",
)


def normalize_host(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(normalize_host(host).strip("[]"))
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """'login.secure.paypal.co.uk' -> 'paypal.co.uk'. Falls back to the host."""
    host = normalize_host(host)
    if not host or is_ip_address(host):
        return host
    parts = _extract(host)
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return host


def tld(host: str) -> str:
    return _extract(normalize_host(host)).suffix.rsplit(".", 1)[-1]


def decode_idn(host: str) -> str:
    """Decode punycode labels (xn--...) to Unicode, if any."""
    labels = []
    for label in normalize_host(host).split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def has_non_ascii(host: str) -> bool:
    return "xn--" in normalize_host(host) or any(ord(c) > 127 for c in host)


def skeleton(text: str) -> str:
    """Collapse visually confusable characters so look-alikes compare equal."""
    text = text.lower().translate(_CONFUSABLES)
    for multi, single in _MULTI_CHAR_CONFUSABLES:
        text = text.replace(multi, single)
    return re.sub(r"[^a-z]", "", text)


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (small strings only)."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def find_impersonated_brand(host: str) -> str | None:
    """Return the brand a domain imitates, or None.

    Catches homoglyphs (paypa1.com, раypal.com), typos (paypall.com) and
    brand-in-domain tricks (paypal-secure-login.com). A brand's own
    legitimate domains never match.
    """
    domain = registrable_domain(decode_idn(host))
    if not domain:
        return None
    label = domain.split(".", 1)[0]
    label_skeleton = skeleton(label)
    tokens = re.split(r"[-_.]", label)

    for brand, legit_domains in BRANDS.items():
        if domain in legit_domains or label == brand:
            # Exact brand label on any suffix (google.co.il, amazon.de) is
            # treated as legitimate: country domains are too common to flag.
            continue
        if label_skeleton == brand:
            return brand  # homoglyph look-alike
        if len(brand) >= 5 and len(label) >= 5 and edit_distance(label, brand) == 1:
            return brand  # one-character typo
        if len(brand) >= 4 and brand in tokens:
            return brand  # paypal-secure.com
        if len(brand) >= 5 and brand in label_skeleton:
            rest = label_skeleton.replace(brand, "", 1)
            if any(word in rest for word in _PHISHING_WORDS):
                return brand  # securepaypallogin.com (but not pineapple.com)
    return None
