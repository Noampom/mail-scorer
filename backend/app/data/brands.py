"""Brands that phishing commonly impersonates, with their legitimate domains.

Keys are the words we look for in display names and domains. Values are the
registrable domains that are allowed to use that name. Kept as plain data so
it can be extended without touching analyzer code.
"""

BRANDS: dict[str, frozenset[str]] = {
    "paypal": frozenset({"paypal.com", "paypal-communications.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "microsoft": frozenset({
        "microsoft.com", "outlook.com", "live.com", "office.com",
        "microsoftonline.com", "microsoftstore.com", "microsoft365.com",
    }),
    "outlook": frozenset({"outlook.com", "microsoft.com"}),
    "google": frozenset({
        "google.com", "gmail.com", "youtube.com", "googlemail.com",
        "googleusercontent.com", "googleapis.com", "gstatic.com", "withgoogle.com",
    }),
    "gmail": frozenset({"google.com", "gmail.com", "googlemail.com"}),
    "amazon": frozenset({"amazon.com", "amazonaws.com", "amazonses.com"}),
    "netflix": frozenset({"netflix.com", "netflix.net"}),
    "facebook": frozenset({"facebook.com", "facebookmail.com", "meta.com"}),
    "instagram": frozenset({"instagram.com", "facebookmail.com"}),
    "linkedin": frozenset({"linkedin.com", "licdn.com"}),
    "dropbox": frozenset({"dropbox.com", "dropboxmail.com", "dropboxusercontent.com"}),
    "docusign": frozenset({"docusign.com", "docusign.net"}),
    "dhl": frozenset({"dhl.com", "dhl.co.il"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "github": frozenset({"github.com", "githubusercontent.com", "githubassets.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "binance": frozenset({"binance.com"}),
    # Israeli brands commonly used in local phishing campaigns.
    "leumi": frozenset({"leumi.co.il"}),
    "hapoalim": frozenset({"bankhapoalim.co.il"}),
    "mizrahi": frozenset({"mizrahi-tefahot.co.il"}),
    "discountbank": frozenset({"discountbank.co.il"}),
    "israelpost": frozenset({"israelpost.co.il"}),
}

_DISPLAY_NAMES = {
    "paypal": "PayPal", "linkedin": "LinkedIn", "github": "GitHub", "docusign": "DocuSign",
    "dhl": "DHL", "ups": "UPS", "fedex": "FedEx", "israelpost": "Israel Post",
    "discountbank": "Discount Bank", "hapoalim": "Bank Hapoalim", "leumi": "Bank Leumi",
    "mizrahi": "Mizrahi-Tefahot",
}


def brand_label(brand: str) -> str:
    return _DISPLAY_NAMES.get(brand, brand.title())


# Free mailbox providers: anyone can register an address here.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "aol.com", "icloud.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "walla.co.il", "zoho.com",
})

URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id",
})

# TLDs that are cheap or frequently abused in phishing campaigns.
SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work",
    "click", "link", "rest", "country", "kim", "loan", "support", "icu",
})
