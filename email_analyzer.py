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

def safe_text(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return str(value)

    return str(value)


def get_email_body(message):
    """
    Extract plain text / HTML body from an email.
    """

    plain_parts = []
    html_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()
            disposition = str(
                part.get("Content-Disposition", "")
            ).lower()

            if "attachment" in disposition:
                continue

            try:
                content = part.get_content()
            except Exception:
                try:
                    payload = part.get_payload(
                        decode=True
                    )

                    content = safe_text(payload)

                except Exception:
                    continue

            if content_type == "text/plain":
                plain_parts.append(
                    safe_text(content)
                )

            elif content_type == "text/html":
                html_parts.append(
                    safe_text(content)
                )

    else:

        try:
            content = message.get_content()
        except Exception:
            content = safe_text(
                message.get_payload(
                    decode=True
                )
            )

        if message.get_content_type() == "text/html":
            html_parts.append(
                safe_text(content)
            )
        else:
            plain_parts.append(
                safe_text(content)
            )

    if plain_parts:
        return "\n".join(plain_parts)

    if html_parts:
        return "\n".join(html_parts)

    return ""


def extract_ips(text):
    """
    Extract IPv4 and IPv6 addresses.
    """

    found = []

    # IPv4
    ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    for match in re.findall(
        ipv4_pattern,
        text
    ):

        try:

            ipaddress.ip_address(match)

            if match not in found:
                found.append(match)

        except ValueError:
            pass

    # IPv6
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"

    for match in re.findall(
        ipv6_pattern,
        text
    ):

        try:

            ipaddress.ip_address(match)

            if match not in found:
                found.append(match)

        except ValueError:
            pass

    return found


def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs.
    """

    pattern = r'https?://[^\s<>"\'\]\)]+'

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    cleaned = []

    for url in urls:

        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def get_domain(url):

    try:

        parsed = urlparse(url)

        return parsed.netloc.lower()

    except Exception:

        return ""


def analyze_url(url):
    """
    Basic suspicious URL detection.
    """

    reasons = []

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        path = parsed.path.lower()

        full_url = url.lower()

        # ----------------------------------------------------
        # IP based URL
        # ----------------------------------------------------

        hostname = parsed.hostname

        if hostname:

            try:

                ipaddress.ip_address(
                    hostname
                )

                reasons.append(
                    "URL uses an IP address instead of a domain name"
                )

            except ValueError:
                pass

        # ----------------------------------------------------
        # Suspicious keywords
        # ----------------------------------------------------

        suspicious_words = [
            "login",
            "verify",
            "verification",
            "account",
            "secure",
            "security",
            "password",
            "update",
            "confirm",
            "signin",
            "wallet",
            "payment",
            "invoice",
            "bank"
        ]

        matched_words = []

        for word in suspicious_words:

            if word in full_url:

                matched_words.append(word)

        if matched_words:

            reasons.append(
                "Contains security/account related keywords: "
                + ", ".join(matched_words)
            )

        # ----------------------------------------------------
        # URL encoding
        # ----------------------------------------------------

        if "%" in url:

            reasons.append(
                "URL contains encoded characters"
            )

        # ----------------------------------------------------
        # Excessive subdomains
        # ----------------------------------------------------

        if domain.count(".") >= 3:

            reasons.append(
                "Domain contains an unusually high number of subdomains"
            )

        # ----------------------------------------------------
        # Suspicious TLDs
        # ----------------------------------------------------

        suspicious_tlds = [
            ".xyz",
            ".top",
            ".click",
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq"
        ]

        if any(
            domain.endswith(tld)
            for tld in suspicious_tlds
        ):

            reasons.append(
                "Domain uses a commonly abused top-level domain"
            )

        # ----------------------------------------------------
        # Long URL
        # ----------------------------------------------------

        if len(url) > 150:

            reasons.append(
                "URL is unusually long"
            )

    except Exception:

        reasons.append(
            "URL parsing failed"
        )

    return {
        "url": url,
        "domain": domain,
        "reasons": reasons,
        "suspicious": len(reasons) > 0
    }


def extract_received_headers(message):

    headers = []

    for value in message.get_all(
        "Received",
        []
    ):

        headers.append(
            safe_text(value)
        )

    return headers


def parse_authentication(message):

    result = {
        "spf": "UNKNOWN",
        "dkim": "UNKNOWN",
        "dmarc": "UNKNOWN"
    }

    # Authentication-Results
    auth_headers = message.get_all(
        "Authentication-Results",
        []
    )

    combined = " ".join(
        safe_text(x)
        for x in auth_headers
    ).lower()

    # SPF
    if "spf=pass" in combined:
        result["spf"] = "PASS"

    elif "spf=fail" in combined:
        result["spf"] = "FAIL"

    elif "spf=softfail" in combined:
        result["spf"] = "SOFTFAIL"

    elif "spf=neutral" in combined:
        result["spf"] = "NEUTRAL"

    # DKIM
    if "dkim=pass" in combined:
        result["dkim"] = "PASS"

    elif "dkim=fail" in combined:
        result["dkim"] = "FAIL"

    # DMARC
    if "dmarc=pass" in combined:
        result["dmarc"] = "PASS"

    elif "dmarc=fail" in combined:
        result["dmarc"] = "FAIL"

    return result


def get_geolocation_placeholder(ips):

    """
    Keeps the structure ready for an IP geolocation API.

    Actual external API lookup can be added later.
    """

    locations = []

    for ip in ips:

        try:

            ip_obj = ipaddress.ip_address(ip)

            # Private/local IP
            if ip_obj.is_private:

                locations.append({
                    "ip": ip,
                    "country": "Private Network",
                    "region": "N/A",
                    "city": "N/A",
                    "isp": "Private Network",
                    "organization": "Private Network",
                    "latitude": "N/A",
                    "longitude": "N/A",
                    "status": "PRIVATE_IP"
                })

            else:

                locations.append({
                    "ip": ip,
                    "country": "Pending API",
                    "region": "Pending API",
                    "city": "Pending API",
                    "isp": "Pending API",
                    "organization": "Pending API",
                    "latitude": "Pending API",
                    "longitude": "Pending API",
                    "status": "PENDING_API"
                })

        except Exception:

            pass

    return locations


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_email(file_data):

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    sha256 = hashlib.sha256(
        file_data
    ).hexdigest()

    # --------------------------------------------------------
    # PARSE EMAIL
    # --------------------------------------------------------

    message = BytesParser(
        policy=policy.default
    ).parsebytes(
        file_data
    )

    # --------------------------------------------------------
    # BASIC HEADERS
    # --------------------------------------------------------

    raw_from = safe_text(
        message.get(
            "From",
            ""
        )
    )

    raw_to = safe_text(
        message.get(
            "To",
            ""
        )
    )

    raw_reply_to = safe_text(
        message.get(
            "Reply-To",
            ""
        )
    )

    return_path = safe_text(
        message.get(
            "Return-Path",
            ""
        )
    )

    subject = safe_text(
        message.get(
            "Subject",
            ""
        )
    )

    message_id = safe_text(
        message.get(
            "Message-ID",
            ""
        )
    )

    # --------------------------------------------------------
    # PARSE ADDRESSES
    # --------------------------------------------------------

    from_name, from_email = parseaddr(
        raw_from
    )

    reply_name, reply_email = parseaddr(
        raw_reply_to
    )

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    body = get_email_body(
        message
    )

    # --------------------------------------------------------
    # URLS
    # --------------------------------------------------------

    urls = extract_urls(
        body
        + "\n"
        + safe_text(
            message
        )
    )

    url_results = []

    for url in urls:

        url_results.append(
            analyze_url(url)
        )

    suspicious_urls = [
        item
        for item in url_results
        if item["suspicious"]
    ]

    # --------------------------------------------------------
    # IPS
    # --------------------------------------------------------

    received_headers = extract_received_headers(
        message
    )

    header_text = "\n".join(
        received_headers
    )

    ips = extract_ips(
        header_text
        + "\n"
        + safe_text(message)
    )

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    authentication = parse_authentication(
        message
    )

    # --------------------------------------------------------
    # RISK ENGINE
    # --------------------------------------------------------

    risk_score = 0

    risk_factors = []

    indicators = []

    threat_types = []

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if authentication["spf"] == "FAIL":

        risk_score += 25

        risk_factors.append({
            "indicator": "SPF authentication failed",
            "points": 25
        })

        indicators.append(
            "SPF authentication failure detected"
        )

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if authentication["dkim"] == "FAIL":

        risk_score += 20

        risk_factors.append({
            "indicator": "DKIM authentication failed",
            "points": 20
        })

        indicators.append(
            "DKIM authentication failure detected"
        )

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if authentication["dmarc"] == "FAIL":

        risk_score += 25

        risk_factors.append({
            "indicator": "DMARC authentication failed",
            "points": 25
        })

        indicators.append(
            "DMARC authentication failure detected"
        )

    # --------------------------------------------------------
    # Suspicious URLs
    # --------------------------------------------------------

    if suspicious_urls:

        points = min(
            30,
            len(suspicious_urls) * 10
        )

        risk_score += points

        risk_factors.append({
            "indicator": (
                f"{len(suspicious_urls)} suspicious URL(s) detected"
            ),
            "points": points
        })

        indicators.append(
            "Suspicious URL characteristics detected"
        )

        if "PHISHING" not in threat_types:

            threat_types.append(
                "PHISHING"
            )

    # --------------------------------------------------------
    # Reply-To mismatch
    # --------------------------------------------------------

    if (
        from_email
        and reply_email
        and from_email.lower()
        != reply_email.lower()
    ):

        risk_score += 15

        risk_factors.append({
            "indicator": "Reply-To address differs from sender address",
            "points": 15
        })

        indicators.append(
            "Sender and Reply-To addresses do not match"
        )

        if "IMPERSONATION" not in threat_types:

            threat_types.append(
                "IMPERSONATION"
            )

    # --------------------------------------------------------
    # Urgent language
    # --------------------------------------------------------

    urgent_keywords = [
        "urgent",
        "immediately",
        "action required",
        "verify now",
        "account suspended",
        "account locked",
        "final notice",
        "click now",
        "payment required"
    ]

    body_lower = (
        body
        + " "
        + subject
    ).lower()

    matched_urgent = []

    for keyword in urgent_keywords:

        if keyword in body_lower:

            matched_urgent.append(
                keyword
            )

    if matched_urgent:

        points = min(
            15,
            len(matched_urgent) * 5
        )

        risk_score += points

        risk_factors.append({
            "indicator": (
                "Urgent/social-engineering language detected"
            ),
            "points": points
        })

        indicators.append(
            "Urgency-based social engineering indicators detected"
        )

        if "SOCIAL_ENGINEERING" not in threat_types:

            threat_types.append(
                "SOCIAL_ENGINEERING"
            )

    # --------------------------------------------------------
    # IP detection
    # --------------------------------------------------------

    if ips:

        indicators.append(
            f"{len(ips)} IP address(es) extracted from email headers"
        )

    # --------------------------------------------------------
    # Risk limit
    # --------------------------------------------------------

    risk_score = min(
        100,
        risk_score
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if risk_score >= 80:

        classification = "CRITICAL"

    elif risk_score >= 60:

        classification = "HIGH RISK"

    elif risk_score >= 30:

        classification = "SUSPICIOUS"

    else:

        classification = "LOW RISK"

    # --------------------------------------------------------
    # Threat fallback
    # --------------------------------------------------------

    if not threat_types and risk_score >= 30:

        threat_types.append(
            "SUSPICIOUS_EMAIL"
        )

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    network = {
        "ips": ips,
        "geolocation": get_geolocation_placeholder(
            ips
        ),
        "received_headers": received_headers
    }

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence = {
        "sha256": sha256,
        "integrity_status": "VERIFIED",
        "timestamp": datetime.utcnow().isoformat()
    }

    # --------------------------------------------------------
    # CASE ID
    # --------------------------------------------------------

    case_id = (
        "EM-"
        +
        datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    result = {

        "case_id": case_id,

        "analysis_timestamp":
            datetime.utcnow().isoformat(),

        "risk_score":
            risk_score,

        "classification":
            classification,

        "threat_types":
            threat_types,

        "email": {

            "from":
                raw_from,

            "from_email":
                from_email,

            "to":
                raw_to,

            "reply_to":
                raw_reply_to,

            "reply_to_email":
                reply_email,

            "return_path":
                return_path,

            "subject":
                subject,

            "message_id":
                message_id
        },

        "authentication":
            authentication,

        "network":
            network,

        "urls":
            urls,

        "suspicious_urls":
            suspicious_urls,

        "indicators":
            indicators,

        "risk_factors":
            risk_factors,

        "evidence":
            evidence
    }

    return result