"""
url_analyzer.py - turns a URL into features, runs the trained Decision Tree, returns a verdict.

The feature code is the SAME as in the training notebook (phishing_url_decision_tree_colab.ipynb).
If you retrain with different features, update this file to match, otherwise predictions are wrong.

IMPORTANT: this module only reads the URL TEXT. It never opens the URL, so analysing a
dangerous link cannot harm the server.
"""

import math
import os
import re
from collections import Counter
from urllib.parse import urlparse

import joblib
import pandas as pd

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "phishing_url_model.pkl")

PHISH_THRESHOLD = 0.60   # phishing score at or above this -> PHISHING
LEGIT_THRESHOLD = 0.40   # phishing score at or below this -> LEGITIMATE (unless serious red flags)
MAX_URL_LENGTH = 2048

# --------------------------------------------------------------------------- word lists
KNOWN_SLDS = {"co", "com", "ac", "go", "or", "net", "org", "gov", "edu", "sch", "web",
              "mil", "biz", "ne", "gob", "nom", "ltd", "plc"}

# Platforms where anybody can publish a site under a sub-domain (often abused for phishing)
FREE_HOSTING = (
    "repl.co", "replit.app", "replit.dev", "github.io", "gitlab.io", "netlify.app", "web.app",
    "firebaseapp.com", "pages.dev", "workers.dev", "vercel.app", "herokuapp.com", "glitch.me",
    "blogspot.com", "weebly.com", "wixsite.com", "wordpress.com", "000webhostapp.com",
    "sites.google.com", "ukit.me", "godaddysites.com", "square.site", "webflow.io",
    "framer.app", "carrd.co", "myshopify.com", "bubbleapps.io", "azurewebsites.net",
    "cloudfront.net", "r2.dev", "ngrok.io", "trycloudflare.com", "duckdns.org", "ddns.net",
)

SHORTENERS = {
    "bit.ly", "bitly.com", "goo.gl", "tinyurl.com", "tiny.cc", "t.co", "ow.ly", "is.gd",
    "v.gd", "cutt.ly", "shorte.st", "x.co", "tr.im", "adf.ly", "bc.vc", "j.mp", "lnkd.in",
    "rb.gy", "rebrand.ly", "t.ly", "s.id", "shorturl.at", "qr.ae", "po.st", "u.to",
}

KEYWORDS = ["login", "signin", "verify", "verification", "secure", "security", "account",
            "update", "confirm", "banking", "bank", "password", "wallet", "support",
            "service", "free", "bonus", "claim", "billing", "payment", "office365",
            "webmail", "recover", "unlock"]

# Frequently impersonated brands. A domain NAME that merely contains one of them
# (paypal-secure, apple-id-verify) is a look-alike; the brand's own domain (paypal.com) is not.
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram",
          "whatsapp", "linkedin", "dropbox", "ebay", "spotify", "binance", "coinbase", "metamask",
          "outlook", "icloud", "steam", "dhl", "fedex", "bca", "mandiri", "bni", "bri", "dana",
          "ovo", "gopay", "shopee", "tokopedia", "lazada", "telkomsel"]

SENSITIVE_WORDS = ["login", "signin", "verify", "password", "account", "secure", "update", "confirm"]
VOWELS = set("aeiou")


# --------------------------------------------------------------------------- URL helpers
def normalize_url(url):
    """Strip spaces/quotes and add a scheme if the user typed 'example.com/page'."""
    url = str(url).strip().strip("<>\"'")
    if "://" not in url:
        url = "http://" + url
    return url


def is_ip_host(host):
    """True for dotted IPv4, hex-encoded IPv4, single-number IPs, and IPv6 literals."""
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host):
        return True
    if re.fullmatch(r"(0x[0-9a-f]{1,2}\.){3}0x[0-9a-f]{1,2}", host, re.I):
        return True
    if re.fullmatch(r"0x[0-9a-f]+", host, re.I) or re.fullmatch(r"\d{8,10}", host):
        return True
    return ":" in host


def get_host(url):
    """Real host of a URL, lower-case, without a leading 'www.' (text before '@' is ignored)."""
    parsed = urlparse(normalize_url(url))
    host = (parsed.hostname or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def split_host(host):
    """Split a host into (sub_domain, name, suffix, tld).
    Example: login.paypal-secure.co.id -> ("login", "paypal-secure", "co.id", "id")"""
    labels = [p for p in host.split(".") if p]
    if not labels:
        return "", "", "", ""
    suffix_n = 1
    for d in FREE_HOSTING:                                   # free-hosting platform = public suffix
        if host == d or host.endswith("." + d):
            suffix_n = d.count(".") + 1
            break
    else:
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in KNOWN_SLDS:
            suffix_n = 2                                     # e.g. co.id, ac.uk
    suffix = ".".join(labels[-suffix_n:])
    rest = labels[:-suffix_n]
    name = rest[-1] if rest else ""
    sub = ".".join(rest[:-1]) if len(rest) > 1 else ""
    return sub, name, suffix, labels[-1]


def entropy(s):
    """Shannon entropy of a string: higher = more random-looking."""
    if not s:
        return 0.0
    c, n = Counter(s), len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def longest_run(s, pred):
    """Length of the longest run of consecutive characters satisfying pred."""
    best = cur = 0
    for ch in s:
        cur = cur + 1 if pred(ch) else 0
        best = max(best, cur)
    return best


def extract_features(url, top_tlds):
    """Numeric features of the REGISTERED DOMAIN of a URL (same as the training notebook)."""
    host = get_host(url)
    ip = is_ip_host(host)
    sub, name, suffix, tld = split_host(host)
    if ip:
        name, suffix, tld = "", "", ""
    letters = [c for c in name if c.isalpha()]
    f = {
        "is_ip": int(ip),
        "name_len": len(name),
        "name_digits": sum(c.isdigit() for c in name),
        "name_digit_ratio": sum(c.isdigit() for c in name) / max(len(name), 1),
        "name_hyphens": name.count("-"),
        "name_vowel_ratio": sum(c in VOWELS for c in letters) / max(len(letters), 1),
        "name_entropy": entropy(name),
        "name_max_consonant_run": longest_run(name, lambda c: c.isalpha() and c not in VOWELS),
        "name_max_digit_run": longest_run(name, str.isdigit),
        "name_mixed_alnum": int(any(c.isdigit() for c in name) and any(c.isalpha() for c in name)),
        "suffix_len": len(suffix),
        "tld_len": len(tld),
        "is_punycode": int("xn--" in host),
        "is_free_hosting": int(any(host == d or host.endswith("." + d) for d in FREE_HOSTING)),
        "name_keywords": sum(k in name for k in KEYWORDS),
        "brand_lookalike": int(any(b in name and name != b for b in BRANDS)),
    }
    for t in top_tlds:
        f[f"tld_{t}"] = int(tld == t)
    f["tld_other"] = int(tld not in top_tlds)
    return f


# --------------------------------------------------------------------------- red flags
def analyze_hints(url):
    """Rule-based red flags. Returns (serious, minor); serious flags can override a 'legitimate' verdict."""
    parsed = urlparse(normalize_url(url))
    host = get_host(url)
    sub, name, suffix, tld = split_host(host)
    serious, minor = [], []

    if "@" in parsed.netloc:
        serious.append("The URL contains '@': the browser ignores everything before it and goes to the host after it.")
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        serious.append("A URL shortener hides the real destination.")
    if "xn--" in host:
        serious.append("Look-alike (punycode, 'xn--') domain.")
    if is_ip_host(host):
        serious.append("An IP address is used instead of a domain name.")
    if "http" in host:
        serious.append("The word 'http(s)' is placed inside the domain to look secure.")
    if sub and re.search(r"(^|\.)(com|net|org|co|gov|edu)(\.|$)", sub):
        serious.append(f"The sub-domain '{sub}' imitates another domain name.")
    if sub and len(sub.split(".")) >= 4:
        serious.append("Unusually many sub-domain levels.")

    brands = [b for b in BRANDS if b in name and name != b]
    kw_name = [k for k in KEYWORDS if k in name]
    kw_sub = [k for k in KEYWORDS if k in sub]
    kw_path = [k for k in SENSITIVE_WORDS if k in (parsed.path + "?" + parsed.query).lower()]
    if brands:
        minor.append(f"The domain name embeds the brand '{brands[0]}' but is not that brand's own domain.")
    if kw_name:
        minor.append(f"The domain name contains bait words: {', '.join(kw_name)}.")
    if kw_sub:
        minor.append(f"The sub-domain contains sensitive words: {', '.join(kw_sub)} (also common on real sites).")
    if kw_path:
        minor.append(f"The path/query contains: {', '.join(kw_path)} (the model does not judge the path).")
    if len(normalize_url(url)) > 100:
        minor.append("The URL is very long.")
    try:
        if parsed.port not in (None, 80, 443):
            minor.append(f"Non-standard port {parsed.port}.")
    except ValueError:
        minor.append("Invalid port number.")
    if parsed.scheme == "http":
        minor.append("The connection is not encrypted (http); the model does not judge the scheme.")
    return serious, minor


# --------------------------------------------------------------------------- model + verdict
class PhishingChecker:
    """Loads the trained bundle once and checks URLs."""

    def __init__(self, model_path=MODEL_PATH):
        # Only load model files you created or trust: pickle can run code when loaded.
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.top_tlds = bundle["top_tlds"]
        self.columns = bundle["columns"]
        self.phish_index = list(self.model.classes_).index(1)

    def check(self, url):
        """Return a JSON-friendly dict, or raise ValueError for unusable input."""
        url = (url or "").strip()
        if not url:
            raise ValueError("Please enter a URL.")
        if len(url) > MAX_URL_LENGTH:
            raise ValueError(f"The URL is too long (maximum {MAX_URL_LENGTH} characters).")
        if re.search(r"\s", url):
            raise ValueError("A URL cannot contain spaces.")
        try:
            host = get_host(url)
        except ValueError:                      # urlparse rejects e.g. malformed IPv6 brackets
            raise ValueError("That does not look like a valid URL.")
        if not host or "." not in host and not is_ip_host(host):
            raise ValueError("Could not find a domain name in that URL.")

        sub, name, suffix, tld = split_host(host)
        row = pd.DataFrame([extract_features(url, self.top_tlds)])[self.columns]   # same column order
        score = float(self.model.predict_proba(row)[0][self.phish_index])          # P(phishing)
        serious, minor = analyze_hints(url)

        if score >= PHISH_THRESHOLD:
            verdict = "PHISHING"
        elif score > LEGIT_THRESHOLD:
            verdict = "UNCERTAIN"
        elif serious:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"

        judged = f"{host} (IP address)" if is_ip_host(host) else (f"{name}.{suffix}" if name else host)
        return {
            "url": normalize_url(url),
            "judged_domain": judged,
            "verdict": verdict,
            "score": round(score, 4),
            "serious_flags": serious,
            "minor_flags": minor,
        }
