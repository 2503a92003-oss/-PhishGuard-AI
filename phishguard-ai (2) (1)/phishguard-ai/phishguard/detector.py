"""Rule-based phishing detection with an optional scikit-learn model.

Nothing here opens, fetches or resolves a link. Every check reads only the text of
the message or the URL string, so it is safe to run on live phishing samples.
"""
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

MODEL_PATH = Path(__file__).with_name("model.joblib")
LOW_MAX, MEDIUM_MAX = 25, 45  # score < 25 Low, < 45 Medium, otherwise High

TLDS = "com|net|org|io|co|info|biz|xyz|top|tk|ml|ga|cf|gq|zip|click|link|ru|cn|site|online|shop|support|work|icu"
URL_RE = re.compile(
    r"(?<![@\w.\-/])((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+(?:%s)\b(?:/[^\s<>\"']*)?)" % TLDS,
    re.I,
)
TRAILING = ".,;:!?)]}>'\""

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support", "icu", "cyou", "sbs", "rest"}
SECOND_LEVEL = {"co.uk", "org.uk", "com.au", "co.jp", "co.in", "com.br", "co.nz", "com.mx", "co.za"}
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com", "amazonses.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
}
LEET = str.maketrans("01345$", "oleass")

# (id, title, why it matters, points, pattern)
TEXT_RULES = [
    ("urgency", "Urgent or pressuring language", "Scammers rush you so you won't stop to check.", 12,
     r"\b(urgent(ly)?|immediately|act now|right away|asap|final (notice|warning)|last (chance|warning)|expires? (today|tonight|soon)|within \d+ (hours?|minutes?|days?)|limited time)\b"),
    ("credentials", "Asks you to verify or update account details", "Real companies rarely ask you to confirm credentials through a message.", 18,
     r"\b(verify|confirm|validate|update|re-?enter|restore)\b[^.\n]{0,40}\b(account|password|identity|log-?in|credentials|billing|payment|card|bank|details|information)\b"),
    ("sensitive", "Mentions sensitive information", "Passwords, PINs, card numbers and recovery phrases should never be sent on request.", 20,
     r"\b(password|passcode|pin|ssn|social security( number)?|cvv|security code|card number|one[- ]time (code|password)|otp|seed phrase|recovery phrase|routing number)\b"),
    ("threat", "Threatens account problems", "Fear of losing access is the most common pressure tactic.", 15,
     r"\b(account (will be|has been|is) (closed|locked|suspended|terminated|limited|restricted|on hold)|(been|was) (locked|suspended|compromised)|legal action|arrest|unauthori[sz]ed (login|access|activity|transaction)|suspicious (activity|sign[- ]?in|login)|permanent(ly)? (closure|deactivat\w*|delet\w*))\b"),
    ("money", "Mentions money, prizes or payment trouble", "Fake refunds, prizes and failed payments are classic lures.", 15,
     r"\b(gift cards?|wire transfer|bitcoin|crypto(currency)?|wallet|western union|prize|lottery|jackpot|you(?:'ve| have) won|inheritance|refund|payment (failed|declined|overdue)|overdue|pay (a )?(small )?fee)\b"),
    ("greeting", "Generic greeting", "Messages from a company that knows you usually use your name.", 8,
     r"\bdear (customer|user|client|member|valued|account holder|sir|madam|friend)\b"),
    ("click", "Pushes you to click or open something", "Phishing messages want you to act before you think.", 8,
     r"\b(click (here|below|the link|this link)|tap (here|the link)|open the attachment|enable (content|macros)|download (the )?attach\w+|log ?in (here|below|now))\b"),
    ("secrecy", "Asks you to keep it secret", "Secrecy stops you from checking with someone you trust.", 10,
     r"\b(do not (tell|share|discuss)|keep this (confidential|secret|private)|don'?t tell)\b"),
]
TEXT_RULES = [(i, t, d, p, re.compile(rx, re.I)) for i, t, d, p, rx in TEXT_RULES]


def level_for(score):
    return "Low" if score < LOW_MAX else "Medium" if score < MEDIUM_MAX else "High"


def registered_domain(host):
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host):
    if host.isdigit() and len(host) >= 8:  # decimal-encoded IPv4
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_hit(host):
    """Return a brand name if the host imitates it without belonging to it."""
    reg = registered_domain(host)
    tokens = re.split(r"[.\-_]", host.translate(LEET).replace("rn", "m").replace("vv", "w"))
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        if any(t == brand or (len(brand) >= 5 and t.startswith(brand)) for t in tokens):
            return brand
    return None


def _url_findings(raw, add, span):
    try:
        parsed = urlparse(raw if "://" in raw else "//" + raw)
        host = (parsed.hostname or "").lower().strip(".")
        port = parsed.port
    except ValueError:
        add("malformed_url", "Link is malformed", "Disguised links often can't be parsed normally.", 10, [raw], [span], "url")
        return
    if not host:
        return
    ev, spans = [raw], [span]

    def hit(rid, title, detail, pts):
        add(rid, title, detail, pts, ev, spans, "url")

    reg = registered_domain(host)
    sub = host[: -len(reg)].strip(".") if host.endswith(reg) else ""
    if raw.lower().startswith("http://"):
        hit("http", "Link is not encrypted", "It uses http instead of https, so anything typed can be read in transit.", 8)
    if _is_ip(host):
        hit("ip_host", "Link points to a raw IP address", "Legitimate services almost always use a domain name.", 25)
    if "@" in parsed.netloc:
        hit("userinfo", "Link hides its real destination with @", "Everything before the @ is ignored; the site after it is where you land.", 25)
    if "xn--" in host:
        hit("punycode", "Link uses look-alike characters", "Internationalised (xn--) domains can imitate trusted names.", 20)
    if reg in SHORTENERS:
        hit("shortener", "Link is shortened", "A short link hides where it really goes.", 12)
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        hit("risky_tld", "Link ends in a domain extension often used for abuse", "Cheap or free extensions show up in many phishing campaigns.", 12)
    if sub and sub.count(".") >= 2:
        hit("subdomains", "Link has many subdomains", "Long chains can bury the real domain at the end.", 10)
    if host.count("-") >= 3:
        hit("hyphens", "Domain has many hyphens", "Strings like secure-login-account-verify are typical of fake sites.", 8)
    if len(raw) > 100:
        hit("long_url", "Link is unusually long", "Length can hide the real destination or tracking tricks.", 6)
    if port and port not in (80, 443):
        hit("port", "Link uses an unusual port", "Normal websites rarely need a custom port.", 8)
    brand = _brand_hit(host)
    if brand:
        hit("brand_lookalike", f"Link imitates {brand.title()}", f"The domain {reg} looks like {brand.title()} but doesn't belong to it.", 30)
    if re.search(r"(login|signin|sign-in|verify|secure|account|password|confirm|webscr|auth)", parsed.path + parsed.query, re.I):
        hit("login_path", "Link path looks like a login or verification page", "Check you are on the company's real domain before signing in.", 6)
    if re.search(r"[?&](url|redirect|redir|next|continue|return|dest)=https?", raw, re.I):
        hit("redirect", "Link redirects to another site", "A redirect parameter can bounce you from a trusted name to a bad one.", 10)


def ml_probability(text):
    """Probability (0-1) that text is phishing, or None when no model is installed."""
    global _MODEL
    if _MODEL is None:
        try:
            import joblib
            _MODEL = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else False
        except Exception:
            _MODEL = False
    if not _MODEL:
        return None
    return float(_MODEL.predict_proba([text])[0][1])


_MODEL = None


def analyze(content, kind="message"):
    content = content.strip()
    found = {}

    def add(rid, title, detail, points, evidence=(), spans=(), category="text"):
        f = found.setdefault(rid, {"id": rid, "title": title, "detail": detail, "points": points,
                                   "category": category, "evidence": [], "spans": []})
        for e in evidence:
            if e not in f["evidence"] and len(f["evidence"]) < 5:
                f["evidence"].append(e)
        f["spans"].extend([list(s) for s in spans if s])

    urls = []
    if kind == "url":
        urls.append((content, 0, len(content)))
    else:
        for rid, title, detail, pts, rx in TEXT_RULES:
            for m in rx.finditer(content):
                add(rid, title, detail, pts, [m.group(0)], [(m.start(), m.end())])
        if content.count("!") >= 3:
            add("shouting", "Heavy use of exclamation marks", "Hype and alarm are common in scam messages.", 4)
        for m in URL_RE.finditer(content):
            url = m.group(1).rstrip(TRAILING)
            if url and len(urls) < 10:
                urls.append((url, m.start(1), m.start(1) + len(url)))

    for url, start, end in urls:
        _url_findings(url, add, (start, end))

    if kind != "url":  # brand named in the text but every link goes elsewhere
        regs = {registered_domain((urlparse(u if "://" in u else "//" + u).hostname or "")) for u, _, _ in urls}
        for brand, official in BRANDS.items():
            m = re.search(r"\b%s\b" % brand, content, re.I)
            if m and regs and not (regs & official):
                add("brand_mismatch", "Names a company but links somewhere else",
                    f"The message mentions {brand.title()}, yet none of its links go to {brand.title()}.",
                    15, [m.group(0)], [(m.start(), m.end())])

    rule_score = min(100, sum(f["points"] for f in found.values()))
    score, ml = rule_score, None
    if kind != "url":
        ml = ml_probability(content)
    if ml is not None:  # the model can raise a score, never lower it
        score = max(rule_score, round(0.6 * rule_score + 40 * ml))
        if ml >= 0.7:
            add("ml", "Wording resembles known phishing", f"The trained model rated this {ml:.0%} similar to phishing examples.", 0, category="model")

    findings = sorted(found.values(), key=lambda f: -f["points"])
    return {"kind": kind, "score": score, "level": level_for(score), "rule_score": rule_score,
            "ml_score": ml, "findings": findings, "urls": [u for u, _, _ in urls]}
