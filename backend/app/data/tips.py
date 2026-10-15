"""'How to spot this yourself' tips, shown with each finding (teach mode).

The goal is that users learn the pattern, not just trust the score.
Keyed by finding id; ids without a tip simply show none.
"""

TIPS: dict[str, str] = {
    "auth.dmarc_fail": "In Gmail, click the arrow next to the sender and check 'mailed-by' and 'signed-by'. "
                       "If they don't match the company, be suspicious.",
    "auth.spf_fail": "A failed server check means the email may not come from where it claims. "
                     "Contact the company through its official website instead of replying.",
    "auth.spf_softfail": "Treat this like an unverified caller: confirm through a channel you already trust.",
    "auth.dkim_fail": "A broken signature can mean the message was forged or altered on the way.",
    "auth.unverified": "Be extra careful with unverified senders who ask you to click, pay or log in.",
    "sender.display_name_address": "Always look at the actual address in <angle brackets>, not the name shown.",
    "sender.brand_display_name": "Anyone can type any name. Companies send from their own domain, never from Gmail or random domains.",
    "sender.lookalike_domain": "Read the domain letter by letter: 'rn' can look like 'm', and '1' like 'l'.",
    "sender.idn_domain": "Non-Latin letters can be identical to Latin ones on screen. Type the address yourself instead.",
    "sender.reply_to_mismatch": "Before replying, check who your reply will actually go to.",
    "sender.missing": "Legitimate services always have a clear sender address.",
    "links.mismatch": "Hover over a link (or long-press on mobile) to see where it really goes before clicking.",
    "links.lookalike": "Instead of clicking, open a new tab and type the company's address yourself.",
    "links.script": "Never click links that start with 'javascript:' or 'data:'.",
    "links.ip": "Real companies use named websites. A number like 192.0.2.15 in a link is a red flag.",
    "links.userinfo": "In a web address, everything before '@' is ignored. Look at what comes after it.",
    "links.idn": "Type the address yourself rather than trusting how a link looks.",
    "links.shortener": "Use a link-expander service to preview where a short link goes.",
    "links.tld": "Be extra careful with unusual endings like .xyz, .top or .zip.",
    "content.urgency": "Pressure to act fast is a manipulation technique. Slow down: real deadlines can be verified.",
    "content.credentials": "Legitimate services never ask you to confirm a password by email. Log in through the official app instead.",
    "content.money": "Verify any money request by phone, using a number you already have, not one in the email.",
    "content.extortion": "Don't pay or reply. These are mass emails. If it quotes a real password, change that password.",
    "content.crypto_wallet": "Crypto payments can't be reversed. Never send crypto because of an email.",
    "content.ai_injection": "Hidden text aimed at software is a deliberate deception. Report the email as phishing.",
    "content.invisible_chars": "Invisible characters are used to slip past filters. Treat the email with caution.",
    "content.hidden_text": "Hidden content means the email shows different things to you and to filters.",
    "attachments.executable": "Never open programs or scripts you received by email, even from people you know.",
    "attachments.double_ext": "Turn on 'show file extensions' in Windows so names like invoice.pdf.exe are visible.",
    "attachments.macro": "If an Office file asks you to 'Enable content' or 'Enable macros', close it.",
    "attachments.web_page": "An HTML attachment that asks you to sign in is almost always phishing.",
    "links.safe_browsing": "Chrome would also warn you about this site. Never click past a red warning page.",
    "links.urlhaus": "Links that download files are a common malware route. Don't open downloads you didn't expect.",
    "links.new_domain": "Brand-new websites asking for logins or payments are a classic phishing pattern.",
    "sender.new_domain": "A company emailing you from a domain created last week is a strong warning sign.",
    "attachments.virustotal_malware": "Delete the email. If you opened the file, disconnect from the network and contact IT.",
    "attachments.virustotal_flagged": "Don't open the file unless you can confirm with the sender through another channel.",
    "content.ai_assessment": "Ask yourself what the email wants you to do, and whether you would expect that request.",
    "attachments.archive": "Only open archives you were expecting, and scan them first.",
}
