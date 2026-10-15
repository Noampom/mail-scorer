"""Attachment risk from metadata only.

The add-on sends file names, types, sizes and SHA-256 hashes, never the
files themselves, so private documents never leave the user's mailbox.
Hashes allow reputation lookups (phase 5) without uploading anything.
"""

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.parsing import ParsedEmail

EXECUTABLE = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "ps1", "hta", "jar", "lnk", "cpl", "reg", "dll", "iso", "img", "vhd", "appx",
}
MACRO_OFFICE = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
WEB_PAGE = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"}
ARCHIVE = {"zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"}
DOCUMENT_DISGUISE = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "ppt", "pptx"}


def _extensions(name: str) -> list[str]:
    parts = name.lower().strip().rstrip(".").split(".")
    return [p.strip() for p in parts[1:]] if len(parts) > 1 else []


def analyze(email: ParsedEmail) -> list[Finding]:
    groups: dict[str, list[str]] = {}
    for attachment in email.attachments:
        name = attachment.name or "(unnamed)"
        exts = _extensions(name)
        if not exts:
            continue
        final = exts[-1]
        if len(exts) >= 2 and exts[-2] in DOCUMENT_DISGUISE and final not in DOCUMENT_DISGUISE:
            groups.setdefault("double_ext", []).append(name)
        if final in EXECUTABLE:
            groups.setdefault("executable", []).append(name)
        elif final in MACRO_OFFICE:
            groups.setdefault("macro", []).append(name)
        elif final in WEB_PAGE:
            groups.setdefault("web_page", []).append(name)
        elif final in ARCHIVE:
            groups.setdefault("archive", []).append(name)

    specs = {
        "executable": (Severity.CRITICAL, "Attachment is a program or script",
                       "Opening it runs code on your computer. Legitimate senders almost never email programs."),
        "double_ext": (Severity.HIGH, "Attachment hides its real file type",
                       "The file name pretends to be a document (e.g. invoice.pdf.exe) but is something else."),
        "macro": (Severity.HIGH, "Office file with macros",
                  "Macro-enabled Office files can run code when opened and are a common malware delivery method."),
        "web_page": (Severity.HIGH, "Attachment is a web page",
                     "HTML attachments often open a fake login page locally, bypassing link scanners."),
        "archive": (Severity.LOW, "Compressed attachment",
                    "Archives can hide dangerous files from email scanners. Only open if you expected it."),
    }
    return [
        Finding(f"attachments.{kind}", Category.ATTACHMENTS, severity, title, explanation, make_evidence(groups[kind]))
        for kind, (severity, title, explanation) in specs.items()
        if kind in groups
    ]
