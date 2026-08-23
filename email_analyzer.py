from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
from datetime import datetime
import hashlib
import re
import ipaddress


# ============================================================
# HELPERS
# ============================================================

def clean(value):
    if value is None:
        return ""

    return str(value).strip()


def extract_email(value):
    if not value:
        return ""

    return parseaddr(value)[1]


def extract_name(value):
    if not value:
        return ""

    return parseaddr(value)[0]


def unique_list(items):
    result = []

    for item in items:
        if item and item not in result:
            result.append(item)

    return result


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ips(text):
    if not text:
        return []

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(pattern, text)

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)

            if ip not in valid_ips:
                valid_ips.append(ip)

        except ValueError:
            pass

    return valid_ips


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):
    if not text:
        return []

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,);]}>")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_suspicious_urls(urls):

    suspicious = []

    for url in urls:

        try:

            parsed = urlparse(url)

            domain = parsed.netloc.lower()

            reasons = []

            if not domain:
                reasons.append(
                    "Invalid or incomplete domain"
                )

            # IP based URL
            try:

                ipaddress.ip_address(
                    domain.split(":")[0]
                )

                reasons.append(
                    "URL uses an IP address instead of a domain"
                )

            except ValueError:
                pass

            # HTTP instead of HTTPS
            if parsed.scheme.lower() == "http":
                reasons.append(
                    "URL does not use HTTPS"
                )

            # Suspicious keywords
            keywords = [
                "login",
                "verify",
                "verification",
                "secure",
                "account",
                "password",
                "update",
                "confirm",
                "wallet",
                "payment",
                "bank"
            ]

            for keyword in keywords:

                if keyword in url.lower():

                    reasons.append(
                        f"Contains suspicious keyword: {keyword}"
                    )

                    break

            # Long URL
            if len(url) > 150:

                reasons.append(
                    "Unusually long URL"
                )

            # @ symbol
            if "@" in url:

                reasons.append(
                    "URL contains @ symbol"
                )

            if reasons:

                suspicious.append(
                    {
                        "url": url,
                        "domain": domain,
                        "reasons": reasons
                    }
                )

        except Exception:

            suspicious.append(
                {
                    "url": url,
                    "domain": "Unknown",
                    "reasons": [
                        "Unable to parse URL"
                    ]
                }
            )

    return suspicious


# ============================================================
# AUTHENTICATION
# ============================================================

def analyze_authentication(message):

    auth_header = clean(
        message.get(
            "Authentication-Results",
            ""
        )
    )

    received_spf = clean(
        message.get(
            "Received-SPF",
            ""
        )
    )

    combined = (
        auth_header + " " + received_spf
    ).lower()

    # SPF
    if "spf=pass" in combined:
        spf = "PASS"

    elif "spf=fail" in combined:
        spf = "FAIL"

    elif "spf=softfail" in combined:
        spf = "SOFTFAIL"

    elif "spf=neutral" in combined:
        spf = "NEUTRAL"

    else:
        spf = "UNKNOWN"

    # DKIM
    if "dkim=pass" in combined:
        dkim = "PASS"

    elif "dkim=fail" in combined:
        dkim = "FAIL"

    else:
        dkim = "UNKNOWN"

    # DMARC
    if "dmarc=pass" in combined:
        dmarc = "PASS"

    elif "dmarc=fail" in combined:
        dmarc = "FAIL"

    else:
        dmarc = "UNKNOWN"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


# ============================================================
# RECEIVED HEADERS
# ============================================================

def extract_received_headers(message):

    headers = []

    for header in message.get_all(
        "Received",
        []
    ):

        headers.append(
            clean(header)
        )

    return headers


# ============================================================
# SHA256
# ============================================================

def calculate_sha256(content):

    return hashlib.sha256(
        content
    ).hexdigest()


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_email(
    file_content,
    filename
):

    # ========================================================
    # HASH
    # ========================================================

    sha256 = calculate_sha256(
        file_content
    )

    # ========================================================
    # PARSE EMAIL
    # ========================================================

    try:

        message = BytesParser(
            policy=policy.default
        ).parsebytes(
            file_content
        )

    except Exception as error:

        raise ValueError(
            f"Unable to parse EML file: {error}"
        )

    # ========================================================
    # BASIC EMAIL INFORMATION
    # ========================================================

    from_header = clean(
        message.get(
            "From",
            ""
        )
    )

    to_header = clean(
        message.get(
            "To",
            ""
        )
    )

    reply_to_header = clean(
        message.get(
            "Reply-To",
            ""
        )
    )

    return_path = clean(
        message.get(
            "Return-Path",
            ""
        )
    )

    subject = clean(
        message.get(
            "Subject",
            ""
        )
    )

    message_id = clean(
        message.get(
            "Message-ID",
            ""
        )
    )

    from_email = extract_email(
        from_header
    )

    from_name = extract_name(
        from_header
    )

    reply_to_email = extract_email(
        reply_to_header
    )

    # ========================================================
    # BODY
    # ========================================================

    body_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:

                    body_parts.append(
                        part.get_content()
                    )

                except Exception:
                    pass

    else:

        try:

            body_parts.append(
                message.get_content()
            )

        except Exception:
            pass

    body = "\n".join(
        body_parts
    )

    # ========================================================
    # FULL HEADER TEXT
    # ========================================================

    full_headers = ""

    for key, value in message.items():

        full_headers += (
            f"{key}: {value}\n"
        )

    combined_text = (
        full_headers
        + "\n"
        + body
    )

    # ========================================================
    # URLS
    # ========================================================

    urls = extract_urls(
        combined_text
    )

    suspicious_urls = analyze_suspicious_urls(
        urls
    )

    # ========================================================
    # IPS
    # ========================================================

    ips = extract_ips(
        combined_text
    )

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    authentication = analyze_authentication(
        message
    )

    # ========================================================
    # RECEIVED HEADERS
    # ========================================================

    received_headers = extract_received_headers(
        message
    )

    # ========================================================
    # THREAT ANALYSIS
    # ========================================================

    risk_score = 0

    indicators = []

    risk_factors = []

    threat_types = []

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if authentication["spf"] == "FAIL":

        risk_score += 20

        indicators.append(
            "SPF authentication failed"
        )

        risk_factors.append(
            {
                "indicator": "SPF authentication failed",
                "points": 20
            }
        )

    elif authentication["spf"] == "SOFTFAIL":

        risk_score += 10

        indicators.append(
            "SPF authentication returned SOFTFAIL"
        )

        risk_factors.append(
            {
                "indicator": "SPF soft failure",
                "points": 10
            }
        )

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if authentication["dkim"] == "FAIL":

        risk_score += 15

        indicators.append(
            "DKIM authentication failed"
        )

        risk_factors.append(
            {
                "indicator": "DKIM authentication failed",
                "points": 15
            }
        )

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if authentication["dmarc"] == "FAIL":

        risk_score += 20

        indicators.append(
            "DMARC authentication failed"
        )

        risk_factors.append(
            {
                "indicator": "DMARC authentication failed",
                "points": 20
            }
        )

    # --------------------------------------------------------
    # SUSPICIOUS URLS
    # --------------------------------------------------------

    if suspicious_urls:

        points = min(
            len(suspicious_urls) * 10,
            30
        )

        risk_score += points

        indicators.append(
            f"{len(suspicious_urls)} suspicious URL(s) detected"
        )

        risk_factors.append(
            {
                "indicator": "Suspicious URLs detected",
                "points": points
            }
        )

        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )

    # --------------------------------------------------------
    # REPLY-TO MISMATCH
    # --------------------------------------------------------

    if (
        from_email
        and reply_to_email
        and from_email.lower()
        != reply_to_email.lower()
    ):

        risk_score += 15

        indicators.append(
            "Reply-To address differs from sender address"
        )

        risk_factors.append(
            {
                "indicator": "Sender and Reply-To mismatch",
                "points": 15
            }
        )

        if "BEC" not in threat_types:

            threat_types.append(
                "BEC"
            )

    # --------------------------------------------------------
    # SUSPICIOUS SUBJECT
    # --------------------------------------------------------

    suspicious_subject_words = [
        "urgent",
        "verify",
        "verification",
        "account suspended",
        "password",
        "payment",
        "invoice",
        "immediately",
        "action required",
        "security alert"
    ]

    subject_lower = subject.lower()

    matched_subject = None

    for word in suspicious_subject_words:

        if word in subject_lower:

            matched_subject = word
            break

    if matched_subject:

        risk_score += 10

        indicators.append(
            f"Suspicious subject keyword detected: {matched_subject}"
        )

        risk_factors.append(
            {
                "indicator":
                    f"Suspicious subject keyword: {matched_subject}",
                "points": 10
            }
        )

    # --------------------------------------------------------
    # SUSPICIOUS BODY WORDS
    # --------------------------------------------------------

    body_keywords = [
        "verify your account",
        "click here",
        "confirm your identity",
        "reset your password",
        "send password",
        "bank account",
        "wire transfer",
        "gift card"
    ]

    body_match = None

    body_lower = body.lower()

    for keyword in body_keywords:

        if keyword in body_lower:

            body_match = keyword
            break

    if body_match:

        risk_score += 10

        indicators.append(
            f"Suspicious email content detected: {body_match}"
        )

        risk_factors.append(
            {
                "indicator":
                    f"Suspicious body content: {body_match}",
                "points": 10
            }
        )

        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    if ips:

        indicators.append(
            f"{len(ips)} IP address(es) extracted from email"
        )

    # ========================================================
    # CAP SCORE
    # ========================================================

    risk_score = min(
        risk_score,
        100
    )

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    if risk_score >= 80:

        classification = "CRITICAL"

    elif risk_score >= 60:

        classification = "HIGH RISK"

    elif risk_score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "LOW RISK"

    # ========================================================
    # DEFAULT THREAT
    # ========================================================

    if not threat_types and risk_score >= 30:

        threat_types.append(
            "Suspicious Email"
        )

    # ========================================================
    # GEOLOCATION
    # ========================================================

    geolocation = []

    for ip in ips:

        geolocation.append(
            {
                "ip": ip,
                "country": "Pending API",
                "region": "Pending API",
                "city": "Pending API",
                "isp": "Pending API",
                "organization": "Pending API",
                "latitude": "N/A",
                "longitude": "N/A",
                "status": "PENDING"
            }
        )

    # ========================================================
    # CASE ID
    # ========================================================

    case_id = (
        "EG-"
        + datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "case_id": case_id,

        "filename": filename,

        "analysis_timestamp":
            datetime.now().isoformat(),

        "risk_score": risk_score,

        "classification": classification,

        "threat_types": threat_types,

        "email": {

            "from": from_header,

            "from_name": from_name,

            "from_email": from_email,

            "to": to_header,

            "reply_to": reply_to_header,

            "reply_to_email":
                reply_to_email,

            "return_path":
                return_path,

            "subject": subject,

            "message_id": message_id
        },

        "authentication":
            authentication,

        "network": {

            "ips": ips,

            "geolocation":
                geolocation,

            "received_headers":
                received_headers
        },

        "urls": urls,

        "suspicious_urls":
            suspicious_urls,

        "indicators":
            unique_list(indicators),

        "risk_factors":
            risk_factors,

        "evidence": {

            "sha256": sha256,

            "integrity_status":
                "VERIFIED",

            "timestamp":
                datetime.now().isoformat()
        }
    }

    return result