"""What the email says: pressure tactics, requests, threats, hidden tricks.

Phrase lists are deliberately small and explainable: each match is shown
to the user as evidence, so every point added to the score can be traced
back to words actually in the email. English plus common Hebrew phrasing.
"""

import re
from dataclasses import dataclass

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.parsing import ParsedEmail


@dataclass(frozen=True)
class PhraseRule:
    id: str
    severity: Severity
    title: str
    explanation: str
    pattern: re.Pattern


def _rx(*phrases: str) -> re.Pattern:
    return re.compile(r"(?<!\w)(?:" + "|".join(phrases) + r")(?!\w)", re.IGNORECASE)


RULES = (
    PhraseRule(
        "content.urgency", Severity.LOW, "Creates urgency or pressure",
        "The email pushes you to act fast. Pressure is used to stop you from thinking twice.",
        _rx(r"urgent(?:ly)?", r"immediately", r"act now", r"within (?:24|48|72) hours",
            r"final (?:notice|warning|reminder)", r"last chance", r"expires? today",
            r"account (?:will be|has been|is) (?:suspended|closed|locked|disabled|terminated|restricted)",
            r"דחוף", r"באופן מיידי", r"החשבון שלך (?:יושעה|ייחסם|נחסם|הושעה)"),
    ),
    PhraseRule(
        "content.credentials", Severity.MEDIUM, "Asks you to verify your account or log in",
        "Requests to confirm passwords or account details are the core of credential phishing.",
        _rx(r"verify your (?:account|identity|password|email|information)",
            r"confirm your (?:password|account|identity|details|information)",
            r"(?:update|validate) your (?:payment|billing|account|bank)(?: (?:information|details))?",
            r"(?:log ?in|sign in) (?:to|now to) (?:restore|unlock|verify|reactivate|avoid)",
            r"enter your (?:password|credentials|pin|card)",
            r"unusual (?:sign-in|login) activity",
            r"אמת את (?:החשבון|הזהות|הפרטים)", r"עדכן את פרטי"),
    ),
    PhraseRule(
        "content.money", Severity.MEDIUM, "Asks for money or payment details",
        "Requests for gift cards, transfers or bank details are common in fraud and CEO-impersonation scams.",
        _rx(r"gift ?cards?", r"wire transfer", r"bank (?:account )?details", r"payment (?:is )?overdue",
            r"outstanding (?:invoice|payment|balance)", r"you (?:have )?won", r"lottery", r"inheritance",
            r"refund (?:is )?pending", r"כרטיס(?:י)? מתנה", r"העברה בנקאית"),
    ),
    PhraseRule(
        "content.extortion", Severity.HIGH, "Contains threats or blackmail",
        "The email threatens to expose or harm you unless you pay. Mass 'sextortion' emails like this "
        "are almost always bluffs, even when they quote a real old password.",
        _rx(r"(?:i|we) (?:have|'ve) (?:recorded|hacked|access to|infected)",
            r"your (?:device|computer|phone|account) (?:was|has been) (?:hacked|infected|compromised)",
            r"(?:intimate|compromising|explicit|private) (?:video|videos|photos|recordings?)",
            r"webcam", r"i know your password",
            r"(?:send|share|release|forward) (?:it|this|the video|everything) to (?:all )?your contacts",
            r"pay .{0,25}(?:bitcoin|btc|crypto)", r"(?:you have|within) \d+ hours? to pay"),
    ),
    PhraseRule(
        "content.ai_injection", Severity.HIGH, "Contains instructions aimed at AI scanners",
        "The email includes text written to manipulate automated or AI-based security tools. "
        "Legitimate senders have no reason to do this.",
        _rx(r"ignore (?:all )?(?:previous|prior|above|earlier) instructions",
            r"disregard (?:the |all )?(?:previous|above|system|prior) (?:instructions|prompt|rules)",
            r"(?:classify|mark|label|treat|report) this (?:email|message) as (?:safe|legitimate|benign|not spam|clean)",
            r"system prompt", r"you are (?:an? )?(?:ai|language model|llm|assistant)"),
    ),
)

# Cryptocurrency wallet addresses: the payment channel of extortion scams.
_WALLETS = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b"
)
# Invisible characters used to split words and slip past keyword filters.
# (Hebrew direction marks U+200E/F and emoji joiners are excluded on purpose.)
_INVISIBLE_CHARS = "​‌⁠﻿­"
_WORD_SPLITTING = re.compile(f"(?<=[A-Za-z])[{_INVISIBLE_CHARS}]+(?=[A-Za-z])")
_NOT_LETTERS = re.compile(r"[\W\d_]+", re.UNICODE)
_INVISIBLE_THRESHOLD = 5
_HIDDEN_TEXT_THRESHOLD = 500


def analyze(email: ParsedEmail) -> list[Finding]:
    visible = f"{email.subject}\n{email.visible_text}"
    everything = f"{visible}\n{email.hidden_text}"
    findings: list[Finding] = []

    for rule in RULES:
        text = everything if rule.id == "content.ai_injection" else visible
        matches = [m.group(0) for m in rule.pattern.finditer(text)]
        if not matches:
            continue
        severity = rule.severity
        if rule.id == "content.urgency" and len(set(m.lower() for m in matches)) >= 2:
            severity = Severity.MEDIUM  # several pressure phrases together
        explanation = rule.explanation
        if rule.id == "content.ai_injection" and rule.pattern.search(email.hidden_text):
            explanation += " Here the instructions are hidden from human readers."
        findings.append(Finding(rule.id, Category.CONTENT, severity, rule.title, explanation,
                                make_evidence(f"“{m}”" for m in matches)))

    wallets = _WALLETS.findall(visible)
    extortion = next((f for f in findings if f.id == "content.extortion"), None)
    if extortion and wallets:
        # Correlation rule: a threat plus a crypto payment address is the
        # signature of sextortion, stronger than either signal alone.
        findings[findings.index(extortion)] = Finding(
            extortion.id, extortion.category, Severity.CRITICAL, "Blackmail demanding crypto payment",
            extortion.explanation + " It also demands payment to a crypto wallet, the signature of an extortion scam.",
            extortion.evidence,
        )
    if wallets:
        findings.append(Finding(
            "content.crypto_wallet", Category.CONTENT, Severity.MEDIUM,
            "Contains a cryptocurrency wallet address",
            "Crypto payments are untraceable and irreversible, which is why extortion scams demand them.",
            make_evidence(w[:12] + "…" for w in wallets),
        ))

    # Only invisible characters INSIDE words count (P​ayPal). Newsletters
    # pad their hidden preview line with long runs of invisible characters
    # between words; that is a normal marketing technique, not evasion.
    split_words = _WORD_SPLITTING.findall(visible)
    if len(split_words) >= _INVISIBLE_THRESHOLD:
        findings.append(Finding(
            "content.invisible_chars", Category.CONTENT, Severity.MEDIUM,
            "Uses invisible characters inside words",
            "Invisible characters are inserted between letters to break up words and evade spam filters.",
            (f"{len(split_words)} words split by invisible characters",),
        ))

    # Measure real hidden words, not whitespace or invisible padding.
    hidden_letters = len(_NOT_LETTERS.sub("", email.hidden_text))
    if hidden_letters >= _HIDDEN_TEXT_THRESHOLD:
        findings.append(Finding(
            "content.hidden_text", Category.CONTENT, Severity.LOW,
            "Contains a lot of hidden text",
            "Part of the email is invisible to you. Newsletters sometimes hide preview text, but large "
            "hidden blocks are also used to confuse filters.",
            (f"{hidden_letters} hidden letters",),
        ))

    return findings
