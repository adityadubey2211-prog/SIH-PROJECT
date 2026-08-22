from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import hashlib
import ipaddress
import json
import re

from datetime import datetime, timezone


# ============================================================
# EMAIL PARSER
# ============================================================

def parse_email(file_data):
    """
    Parse raw .eml bytes into an EmailMessage object.
    """

    return BytesParser(
        policy=policy.default
    ).parsebytes(file_data)


# ============================================================
# HEADER ANALYSIS
# ============================================================

def analyze_headers(email):
    """
    Extract important email headers.
    """

    sender = email.get(
        "From",
        "Unknown"
    )

    recipient = email.get(
        "To",
        "Unknown"
    )

    reply_to = email.get(
        "Reply-To",
        "Not available"
    )

    subject = email.get(
        "Subject",
        "No subject"
    )

    message_id = email.get(
        "Message-ID",
        "Not available"
    )

    return_path = email.get(
        "Return-Path",
        "Not available"
    )

    received_headers = email.get_all(
        "Received",
        []
    )

    sender_name, sender_email = parseaddr(
        sender
    )

    reply_name, reply_email = parseaddr(
        reply_to
    )

    return {

        "from": sender,

        "from_name": sender_name,

        "from_email": sender_email,

        "to": recipient,

        "reply_to": reply_to,

        "reply_to_email": reply_email,

        "subject": subject,

        "message_id": message_id,

        "return_path": return_path,

        "received_headers": received_headers
    }


# ============================================================
# BODY EXTRACTION
# ============================================================

def extract_body(email):
    """
    Extract readable text from the email.
    """

    plain_text = []
    html_text = []

    if email.is_multipart():

        for part in email.walk():

            content_type = (
                part.get_content_type()
            )

            disposition = (
                part.get_content_disposition()
            )

            # Ignore attachments

            if disposition == "attachment":
                continue

            try:

                content = part.get_content()

            except Exception:

                continue

            if not isinstance(
                content,
                str
            ):

                continue

            if content_type == "text/plain":

                plain_text.append(
                    content
                )

            elif content_type == "text/html":

                html_text.append(
                    content
                )

    else:

        try:

            content = email.get_content()

            if isinstance(
                content,
                str
            ):

                if email.get_content_type() == "text/html":

                    html_text.append(
                        content
                    )

                else:

                    plain_text.append(
                        content
                    )

        except Exception:

            pass


    # Prefer plain text

    if plain_text:

        return "\n".join(
            plain_text
        )


    # Basic HTML cleanup

    if html_text:

        html = "\n".join(
            html_text
        )

        html = re.sub(
            r"<script.*?>.*?</script>",
            " ",
            html,
            flags=re.I | re.S
        )

        html = re.sub(
            r"<style.*?>.*?</style>",
            " ",
            html,
            flags=re.I | re.S
        )

        html = re.sub(
            r"<[^>]+>",
            " ",
            html
        )

        html = re.sub(
            r"\s+",
            " ",
            html
        )

        return html.strip()


    return ""


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(text):
    """
    Extract globally routable IPv4 addresses.
    Private, loopback and reserved IPs are ignored.
    """

    if not text:

        return []


    ip_pattern = (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )


    candidates = re.findall(
        ip_pattern,
        text
    )


    valid_ips = []


    for ip in candidates:

        try:

            address = ipaddress.ip_address(
                ip
            )


            if address.version != 4:
                continue


            # Only public/global IPs

            if not address.is_global:
                continue


            valid_ips.append(
                ip
            )


        except ValueError:

            continue


    return list(
        dict.fromkeys(
            valid_ips
        )
    )


# ============================================================
# IP GEOLOCATION
# ============================================================

def get_ip_geolocation(ip):
    """
    Get basic geolocation information for a public IP.

    Uses ipwho.is for prototype/demo purposes.
    """

    empty_result = {

        "ip": ip,

        "country": "Unknown",

        "region": "Unknown",

        "city": "Unknown",

        "isp": "Unknown",

        "organization": "Unknown",

        "latitude": None,

        "longitude": None,

        "status": "FAILED",

        "source": "ipwho.is"
    }


    if not ip:

        return empty_result


    # --------------------------------------------------------
    # Do not query private/reserved IPs
    # --------------------------------------------------------

    try:

        address = ipaddress.ip_address(
            ip
        )

        if not address.is_global:

            empty_result["status"] = (
                "NON_GLOBAL_IP"
            )

            return empty_result

    except ValueError:

        return empty_result


    # --------------------------------------------------------
    # API request
    # --------------------------------------------------------

    try:

        url = (
            "https://ipwho.is/"
            + ip
        )


        request = Request(
            url,
            headers={
                "User-Agent":
                    "EmailGuard-AI/1.0"
            }
        )


        response = urlopen(
            request,
            timeout=8
        )


        raw_data = response.read()


        data = json.loads(
            raw_data.decode(
                "utf-8"
            )
        )


        if not data.get(
            "success",
            False
        ):

            result = dict(
                empty_result
            )

            result["error"] = (
                data.get(
                    "message",
                    "Geolocation lookup failed"
                )
            )

            return result


        connection = data.get(
            "connection",
            {}
        )


        return {

            "ip": ip,

            "country": data.get(
                "country",
                "Unknown"
            ),

            "region": data.get(
                "region",
                "Unknown"
            ),

            "city": data.get(
                "city",
                "Unknown"
            ),

            "isp": connection.get(
                "isp",
                "Unknown"
            ),

            "organization": connection.get(
                "org",
                "Unknown"
            ),

            "latitude": data.get(
                "latitude"
            ),

            "longitude": data.get(
                "longitude"
            ),

            "status": "SUCCESS",

            "source": "ipwho.is"
        }


    except Exception as e:

        result = dict(
            empty_result
        )

        result["error"] = str(e)

        return result


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email body.
    """

    if not text:

        return []


    url_pattern = (
        r"https?://[^\s<>\"']+"
    )


    urls = re.findall(
        url_pattern,
        text,
        flags=re.IGNORECASE
    )


    cleaned_urls = []


    for url in urls:

        # Remove common punctuation

        url = url.rstrip(
            ".,;:!?)]}>"
        )


        if url not in cleaned_urls:

            cleaned_urls.append(
                url
            )


    return cleaned_urls


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(email_address):

    """
    Extract domain from an email address.
    """

    if not email_address:

        return ""


    _, address = parseaddr(
        email_address
    )


    if "@" not in address:

        return ""


    return (
        address
        .split("@")[-1]
        .lower()
        .strip()
    )


# ============================================================
# EMAIL AUTHENTICATION
# ============================================================

def analyze_authentication(email):
    """
    Analyze SPF, DKIM and DMARC from
    Authentication-Results headers.
    """

    auth_headers = email.get_all(
        "Authentication-Results",
        []
    )


    auth_header = " ".join(
        str(x)
        for x in auth_headers
    ).lower()


    spf = "UNKNOWN"
    dkim = "UNKNOWN"
    dmarc = "UNKNOWN"


    # ========================================================
    # SPF
    # ========================================================

    if re.search(
        r"\bspf\s*=\s*pass\b",
        auth_header
    ):

        spf = "PASS"

    elif re.search(
        r"\bspf\s*=\s*fail\b",
        auth_header
    ):

        spf = "FAIL"

    elif re.search(
        r"\bspf\s*=\s*softfail\b",
        auth_header
    ):

        spf = "SOFTFAIL"

    elif re.search(
        r"\bspf\s*=\s*neutral\b",
        auth_header
    ):

        spf = "NEUTRAL"


    # ========================================================
    # DKIM
    # ========================================================

    if re.search(
        r"\bdkim\s*=\s*pass\b",
        auth_header
    ):

        dkim = "PASS"

    elif re.search(
        r"\bdkim\s*=\s*fail\b",
        auth_header
    ):

        dkim = "FAIL"

    elif re.search(
        r"\bdkim\s*=\s*neutral\b",
        auth_header
    ):

        dkim = "NEUTRAL"


    # ========================================================
    # DMARC
    # ========================================================

    if re.search(
        r"\bdmarc\s*=\s*pass\b",
        auth_header
    ):

        dmarc = "PASS"

    elif re.search(
        r"\bdmarc\s*=\s*fail\b",
        auth_header
    ):

        dmarc = "FAIL"

    elif re.search(
        r"\bdmarc\s*=\s*bestguesspass\b",
        auth_header
    ):

        dmarc = "PASS"


    return {

        "spf": spf,

        "dkim": dkim,

        "dmarc": dmarc
    }


# ============================================================
# LOOKALIKE DOMAIN DETECTION
# ============================================================

def detect_lookalike_domain(sender_domain):

    """
    Detect common impersonation/lookalike patterns.
    """

    if not sender_domain:

        return False


    domain = sender_domain.lower()


    lookalike_patterns = [

        "micros0ft",

        "paypa1",

        "g00gle",

        "faceb00k",

        "amaz0n",

        "apple-support",

        "microsoft-support",

        "secure-payment",

        "account-verify",

        "login-security"
    ]


    for pattern in lookalike_patterns:

        if pattern in domain:

            return True


    return False


# ============================================================
# SUSPICIOUS URL DETECTION
# ============================================================

def analyze_urls(urls):

    """
    Analyze extracted URLs for suspicious characteristics.
    """

    suspicious_urls = []


    suspicious_words = [

        "login",

        "verify",

        "secure",

        "account",

        "update",

        "payment",

        "invoice",

        "password",

        "credential",

        "signin",

        "confirm"
    ]


    for url in urls:

        try:

            parsed = urlparse(
                url
            )


            domain = (
                parsed.hostname
                or ""
            ).lower()


            reasons = []


            # ------------------------------------------------
            # URL uses IP address
            # ------------------------------------------------

            try:

                ipaddress.ip_address(
                    domain
                )

                reasons.append(
                    "URL uses IP address"
                )

            except ValueError:

                pass


            # ------------------------------------------------
            # Suspicious keywords
            # ------------------------------------------------

            for word in suspicious_words:

                if word in url.lower():

                    reasons.append(
                        "Suspicious keyword: "
                        + word
                    )

                    break


            # ------------------------------------------------
            # Long URL
            # ------------------------------------------------

            if len(url) > 150:

                reasons.append(
                    "Unusually long URL"
                )


            # ------------------------------------------------
            # HTTP instead of HTTPS
            # ------------------------------------------------

            if parsed.scheme.lower() == "http":

                reasons.append(
                    "URL does not use HTTPS"
                )


            # ------------------------------------------------
            # URL contains @
            # ------------------------------------------------

            if "@" in parsed.netloc:

                reasons.append(
                    "URL contains @ character"
                )


            # ------------------------------------------------
            # Suspicious encoded content
            # ------------------------------------------------

            if "%" in url:

                reasons.append(
                    "URL contains encoded characters"
                )


            if reasons:

                suspicious_urls.append({

                    "url": url,

                    "domain": domain,

                    "reasons": list(
                        dict.fromkeys(
                            reasons
                        )
                    )
                })


        except Exception:

            continue


    return suspicious_urls


# ============================================================
# THREAT DETECTION
# ============================================================

def detect_threats(
    email,
    body,
    urls,
    authentication
):

    """
    Rule-based phishing / BEC detection.
    """

    indicators = []

    risk_factors = []

    threat_types = []

    risk_score = 0


    headers = analyze_headers(
        email
    )


    sender = headers[
        "from"
    ]

    reply_to = headers[
        "reply_to"
    ]

    subject = headers[
        "subject"
    ]


    sender_domain = extract_domain(
        sender
    )

    reply_domain = extract_domain(
        reply_to
    )


    text = (
        subject
        + " "
        + body
    ).lower()


    # ========================================================
    # REPLY-TO MISMATCH
    # ========================================================

    if (
        sender_domain
        and reply_domain
        and sender_domain != reply_domain
    ):

        indicators.append(
            "Reply-To domain mismatch"
        )


        risk_factors.append({

            "indicator":
                "Reply-To mismatch",

            "points":
                15
        })


        risk_score += 15


        if "BEC" not in threat_types:

            threat_types.append(
                "BEC"
            )


    # ========================================================
    # URGENCY / SOCIAL ENGINEERING
    # ========================================================

    urgency_words = [

        "urgent",

        "immediately",

        "action required",

        "as soon as possible",

        "important",

        "verify now",

        "account suspended",

        "act now",

        "final warning",

        "within 24 hours",

        "within 48 hours"
    ]


    found_urgency = any(
        word in text
        for word in urgency_words
    )


    if found_urgency:

        indicators.append(
            "Urgency or social engineering language"
        )


        risk_factors.append({

            "indicator":
                "Urgency / social engineering",

            "points":
                10
        })


        risk_score += 10


    # ========================================================
    # FINANCIAL REQUEST
    # ========================================================

    financial_words = [

        "payment",

        "invoice",

        "bank account",

        "wire transfer",

        "transfer money",

        "refund",

        "bitcoin",

        "crypto",

        "gift card",

        "bank details",

        "account number",

        "upi",

        "transaction"
    ]


    found_financial = any(
        word in text
        for word in financial_words
    )


    if found_financial:

        indicators.append(
            "Potential financial request"
        )


        risk_factors.append({

            "indicator":
                "Financial request",

            "points":
                15
        })


        risk_score += 15


        if "BEC" not in threat_types:

            threat_types.append(
                "BEC"
            )


    # ========================================================
    # CREDENTIAL REQUEST
    # ========================================================

    credential_words = [

        "password",

        "username",

        "login",

        "sign in",

        "credentials",

        "verify your identity",

        "confirm your account"
    ]


    found_credentials = any(
        word in text
        for word in credential_words
    )


    if found_credentials:

        indicators.append(
            "Potential credential harvesting language"
        )


        risk_factors.append({

            "indicator":
                "Credential request",

            "points":
                15
        })


        risk_score += 15


        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )


    # ========================================================
    # URL DETECTED
    # ========================================================

    if len(urls) > 0:

        indicators.append(
            "URL detected in email"
        )


        risk_factors.append({

            "indicator":
                "URL detected",

            "points":
                10
        })


        risk_score += 10


        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )


    # ========================================================
    # SUSPICIOUS URL
    # ========================================================

    suspicious_urls = analyze_urls(
        urls
    )


    if suspicious_urls:

        indicators.append(
            "Suspicious URL characteristics detected"
        )


        risk_factors.append({

            "indicator":
                "Suspicious URL",

            "points":
                10
        })


        risk_score += 10


        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )


    # ========================================================
    # LOOKALIKE DOMAIN
    # ========================================================

    if detect_lookalike_domain(
        sender_domain
    ):

        indicators.append(
            "Possible lookalike or impersonation domain"
        )


        risk_factors.append({

            "indicator":
                "Lookalike domain",

            "points":
                20
        })


        risk_score += 20


        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )


        if "BEC" not in threat_types:

            threat_types.append(
                "BEC"
            )


    # ========================================================
    # SPF
    # ========================================================

    if authentication["spf"] == "FAIL":

        indicators.append(
            "SPF authentication failed"
        )


        risk_factors.append({

            "indicator":
                "SPF failure",

            "points":
                10
        })


        risk_score += 10


    # ========================================================
    # DKIM
    # ========================================================

    if authentication["dkim"] == "FAIL":

        indicators.append(
            "DKIM authentication failed"
        )


        risk_factors.append({

            "indicator":
                "DKIM failure",

            "points":
                10
        })


        risk_score += 10


    # ========================================================
    # DMARC
    # ========================================================

    if authentication["dmarc"] == "FAIL":

        indicators.append(
            "DMARC authentication failed"
        )


        risk_factors.append({

            "indicator":
                "DMARC failure",

            "points":
                10
        })


        risk_score += 10


    # ========================================================
    # FINAL SCORE
    # ========================================================

    risk_score = min(
        risk_score,
        100
    )


    # ========================================================
    # CLASSIFICATION
    # ========================================================

    if risk_score >= 80:

        classification = (
            "CRITICAL / HIGH RISK"
        )

    elif risk_score >= 60:

        classification = (
            "HIGH RISK"
        )

    elif risk_score >= 30:

        classification = (
            "SUSPICIOUS"
        )

    else:

        classification = (
            "LOW RISK"
        )


    # ========================================================
    # DEFAULT THREAT TYPE
    # ========================================================

    if not threat_types:

        threat_types.append(
            "No major threat detected"
        )


    return {

        "indicators":
            list(
                dict.fromkeys(
                    indicators
                )
            ),

        "risk_score":
            risk_score,

        "classification":
            classification,

        "threat_types":
            threat_types,

        "risk_factors":
            risk_factors,

        "suspicious_urls":
            suspicious_urls
    }


# ============================================================
# INVESTIGATION SUMMARY
# ============================================================

def generate_summary(
    threat_analysis,
    authentication,
    suspicious_urls,
    ips
):

    threat_types = (
        threat_analysis[
            "threat_types"
        ]
    )

    indicators = (
        threat_analysis[
            "indicators"
        ]
    )

    risk_score = (
        threat_analysis[
            "risk_score"
        ]
    )


    # --------------------------------------------------------
    # Main classification
    # --------------------------------------------------------

    if (
        "Phishing" in threat_types
        and "BEC" in threat_types
    ):

        summary = (
            "The analyzed email shows characteristics "
            "associated with both phishing and "
            "Business Email Compromise (BEC)."
        )

    elif "Phishing" in threat_types:

        summary = (
            "The analyzed email shows characteristics "
            "associated with phishing."
        )

    elif "BEC" in threat_types:

        summary = (
            "The analyzed email shows characteristics "
            "associated with Business Email Compromise."
        )

    else:

        summary = (
            "The analyzed email does not show major "
            "known phishing or BEC indicators."
        )


    # --------------------------------------------------------
    # Risk
    # --------------------------------------------------------

    summary += (
        f" The calculated threat score is "
        f"{risk_score}/100."
    )


    # --------------------------------------------------------
    # Indicators
    # --------------------------------------------------------

    if indicators:

        summary += (
            f" The investigation identified "
            f"{len(indicators)} suspicious indicator(s)."
        )


    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    failed_auth = []


    if authentication["spf"] == "FAIL":

        failed_auth.append(
            "SPF"
        )


    if authentication["dkim"] == "FAIL":

        failed_auth.append(
            "DKIM"
        )


    if authentication["dmarc"] == "FAIL":

        failed_auth.append(
            "DMARC"
        )


    if failed_auth:

        summary += (
            " Failed authentication mechanisms: "
            + ", ".join(
                failed_auth
            )
            + "."
        )


    # --------------------------------------------------------
    # Suspicious URLs
    # --------------------------------------------------------

    if suspicious_urls:

        summary += (
            f" {len(suspicious_urls)} suspicious "
            "URL(s) require further investigation."
        )


    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    if ips:

        summary += (
            " The email contains observed public "
            "mail infrastructure IP address(es): "
            + ", ".join(ips)
            + "."
        )


    return summary


# ============================================================
# EVIDENCE HASH
# ============================================================

def generate_evidence_hash(file_data):

    """
    Generate SHA-256 hash of original .eml file.
    """

    return hashlib.sha256(
        file_data
    ).hexdigest()


# ============================================================
# TIMESTAMP
# ============================================================

def get_timestamp():

    """
    Generate UTC analysis timestamp.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_email(file_data):

    """
    Complete EmailGuard analysis pipeline.
    """

    # ========================================================
    # PARSE EMAIL
    # ========================================================

    email_message = parse_email(
        file_data
    )


    # ========================================================
    # HEADERS
    # ========================================================

    headers = analyze_headers(
        email_message
    )


    # ========================================================
    # BODY
    # ========================================================

    body = extract_body(
        email_message
    )


    # ========================================================
    # RECEIVED HEADERS
    # ========================================================

    received_headers = headers[
        "received_headers"
    ]


    received_text = "\n".join(
        str(header)
        for header in received_headers
    )


    # ========================================================
    # IP EXTRACTION
    # ========================================================

    ips = extract_ips(
        received_text
    )


    # ========================================================
    # IP GEOLOCATION
    # ========================================================

    geolocation = []


    # Limit API calls to first 5 public IPs

    for ip in ips[:5]:

        location = get_ip_geolocation(
            ip
        )

        geolocation.append(
            location
        )


    # ========================================================
    # URL EXTRACTION
    # ========================================================

    urls = extract_urls(
        body
    )


    # ========================================================
    # AUTHENTICATION
    # ========================================================

    authentication = analyze_authentication(
        email_message
    )


    # ========================================================
    # THREAT DETECTION
    # ========================================================

    threat_analysis = detect_threats(

        email_message,

        body,

        urls,

        authentication
    )


    # ========================================================
    # AI / INVESTIGATION SUMMARY
    # ========================================================

    summary = generate_summary(

        threat_analysis,

        authentication,

        threat_analysis[
            "suspicious_urls"
        ],

        ips
    )


    # ========================================================
    # EVIDENCE HASH
    # ========================================================

    evidence_hash = generate_evidence_hash(
        file_data
    )


    # ========================================================
    # TIMESTAMP
    # ========================================================

    timestamp = get_timestamp()


    # ========================================================
    # CASE ID
    # ========================================================

    case_id = (
        "EM-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S"
        )
    )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        # ----------------------------------------------------
        # CASE
        # ----------------------------------------------------

        "case_id":
            case_id,

        "analysis_timestamp":
            timestamp,


        # ----------------------------------------------------
        # THREAT
        # ----------------------------------------------------

        "risk_score":
            threat_analysis[
                "risk_score"
            ],

        "classification":
            threat_analysis[
                "classification"
            ],

        "threat_types":
            threat_analysis[
                "threat_types"
            ],


        # ----------------------------------------------------
        # EMAIL
        # ----------------------------------------------------

        "email": {

            "from":
                headers[
                    "from"
                ],

            "from_name":
                headers[
                    "from_name"
                ],

            "from_email":
                headers[
                    "from_email"
                ],

            "to":
                headers[
                    "to"
                ],

            "reply_to":
                headers[
                    "reply_to"
                ],

            "subject":
                headers[
                    "subject"
                ],

            "message_id":
                headers[
                    "message_id"
                ],

            "return_path":
                headers[
                    "return_path"
                ]
        },


        # ----------------------------------------------------
        # AUTHENTICATION
        # ----------------------------------------------------

        "authentication": {

            "spf":
                authentication[
                    "spf"
                ],

            "dkim":
                authentication[
                    "dkim"
                ],

            "dmarc":
                authentication[
                    "dmarc"
                ]
        },


        # ----------------------------------------------------
        # NETWORK
        # ----------------------------------------------------

        "network": {

            "ips":
                ips,

            "received_headers":
                received_headers,

            "geolocation":
                geolocation
        },


        # ----------------------------------------------------
        # URLS
        # ----------------------------------------------------

        "urls":
            urls,

        "suspicious_urls":
            threat_analysis[
                "suspicious_urls"
            ],


        # ----------------------------------------------------
        # THREAT INDICATORS
        # ----------------------------------------------------

        "indicators":
            threat_analysis[
                "indicators"
            ],

        "risk_factors":
            threat_analysis[
                "risk_factors"
            ],


        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        "ai_summary":
            summary,


        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        "evidence": {

            "sha256":
                evidence_hash,

            "integrity_status":
                "VERIFIED",

            "timestamp":
                timestamp
        }
    }


    return result