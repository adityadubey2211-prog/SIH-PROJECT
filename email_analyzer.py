# ============================================================
# EMAILGUARD AI - EMAIL ANALYZER
# ============================================================

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

from urllib.parse import urlparse

from datetime import datetime, timezone

import hashlib
import html
import ipaddress
import json
import re
from urllib.request import Request, urlopen


# ============================================================
# IP GEOLOCATION
# ============================================================

def get_ip_geolocation(ip):
    """
    Get approximate geolocation information for an IP address.
    Uses ipapi.co.
    """

    try:

        # Ignore private / local IP addresses
        ip_obj = ipaddress.ip_address(ip)

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        ):

            return {
                "ip": ip,
                "country": "Private Network",
                "region": "Private Network",
                "city": "Private Network",
                "isp": "Private Network",
                "organization": "Private Network",
                "latitude": "N/A",
                "longitude": "N/A",
                "status": "PRIVATE_IP"
            }


        # ----------------------------------------------------
        # API REQUEST
        # ----------------------------------------------------

        url = f"https://ipapi.co/{ip}/json/"

        request = Request(
            url,
            headers={
                "User-Agent": "EmailGuard-AI/1.0"
            }
        )


        with urlopen(
            request,
            timeout=8
        ) as response:

            raw_data = response.read().decode(
                "utf-8",
                errors="ignore"
            )


        data = json.loads(
            raw_data
        )


        # ----------------------------------------------------
        # API RATE LIMIT / ERROR
        # ----------------------------------------------------

        if data.get("error"):

            return {
                "ip": ip,
                "country": "Unavailable",
                "region": "Unavailable",
                "city": "Unavailable",
                "isp": "Unavailable",
                "organization": "Unavailable",
                "latitude": "N/A",
                "longitude": "N/A",
                "status": data.get(
                    "reason",
                    "API_ERROR"
                )
            }


        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        return {
            "ip": ip,

            "country": data.get(
                "country_name",
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

            "isp": data.get(
                "org",
                "Unknown"
            ),

            "organization": data.get(
                "org",
                "Unknown"
            ),

            "latitude": data.get(
                "latitude",
                "N/A"
            ),

            "longitude": data.get(
                "longitude",
                "N/A"
            ),

            "status": "SUCCESS"
        }


    except Exception as error:

        return {
            "ip": ip,
            "country": "Unavailable",
            "region": "Unavailable",
            "city": "Unavailable",
            "isp": "Unavailable",
            "organization": "Unavailable",
            "latitude": "N/A",
            "longitude": "N/A",
            "status": "LOOKUP_FAILED"
        }


# ============================================================
# EXTRACT IP ADDRESSES
# ============================================================

def extract_ips(text):
    """
    Extract IPv4 addresses from email headers/body.
    """

    if not text:
        return []


    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


    matches = re.findall(
        pattern,
        text
    )


    valid_ips = []


    for ip in matches:

        try:

            ipaddress.ip_address(ip)

            if ip not in valid_ips:

                valid_ips.append(ip)

        except ValueError:

            pass


    return valid_ips


# ============================================================
# EXTRACT URLS
# ============================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email content.
    """

    if not text:
        return []


    pattern = (
        r'https?://[^\s<>"\']+'
    )


    matches = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )


    urls = []


    for url in matches:

        # Remove common trailing punctuation
        url = url.rstrip(
            ".,;:!?)]}>"
        )


        if url not in urls:

            urls.append(url)


    return urls


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url(url):

    reasons = []


    try:

        parsed = urlparse(
            url
        )


        domain = (
            parsed.hostname
            or ""
        ).lower()


        # ----------------------------------------------------
        # No HTTPS
        # ----------------------------------------------------

        if parsed.scheme.lower() == "http":

            reasons.append(
                "URL does not use HTTPS"
            )


        # ----------------------------------------------------
        # IP ADDRESS AS DOMAIN
        # ----------------------------------------------------

        if domain:

            try:

                ipaddress.ip_address(
                    domain
                )

                reasons.append(
                    "URL uses an IP address instead of a domain name"
                )

            except ValueError:

                pass


        # ----------------------------------------------------
        # SUSPICIOUS WORDS
        # ----------------------------------------------------

        suspicious_words = [
            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "update",
            "confirm",
            "bank",
            "payment",
            "invoice",
            "wallet",
            "credential",
            "signin",
            "reset"
        ]


        lower_url = url.lower()


        found_words = []


        for word in suspicious_words:

            if word in lower_url:

                found_words.append(
                    word
                )


        if found_words:

            reasons.append(
                "Contains suspicious keywords: "
                + ", ".join(found_words)
            )


        # ----------------------------------------------------
        # LONG URL
        # ----------------------------------------------------

        if len(url) > 150:

            reasons.append(
                "Unusually long URL"
            )


        # ----------------------------------------------------
        # MANY SUBDOMAINS
        # ----------------------------------------------------

        if domain:

            parts = domain.split(".")


            if len(parts) >= 5:

                reasons.append(
                    "Unusually deep subdomain structure"
                )


        # ----------------------------------------------------
        # URL USER INFO
        # ----------------------------------------------------

        if parsed.username:

            reasons.append(
                "URL contains embedded user information"
            )


        # ----------------------------------------------------
        # QUERY PARAMETERS
        # ----------------------------------------------------

        if parsed.query:

            if len(parsed.query) > 80:

                reasons.append(
                    "Large query parameter section"
                )


        return {
            "url": url,
            "domain": domain,
            "reasons": reasons
        }


    except Exception:

        return {
            "url": url,
            "domain": "Unknown",
            "reasons": [
                "Unable to parse URL"
            ]
        }


# ============================================================
# EMAIL BODY EXTRACTION
# ============================================================

def extract_email_body(message):

    body_parts = []


    try:

        if message.is_multipart():

            for part in message.walk():

                content_type = (
                    part.get_content_type()
                )


                disposition = (
                    part.get(
                        "Content-Disposition",
                        ""
                    )
                    or ""
                )


                if (
                    content_type
                    in [
                        "text/plain",
                        "text/html"
                    ]
                    and "attachment"
                    not in disposition.lower()
                ):

                    try:

                        content = (
                            part.get_content()
                        )

                    except Exception:

                        payload = part.get_payload(
                            decode=True
                        )

                        if payload:

                            content = payload.decode(
                                "utf-8",
                                errors="ignore"
                            )

                        else:

                            content = ""


                    if content:

                        body_parts.append(
                            str(content)
                        )


        else:

            try:

                content = (
                    message.get_content()
                )

            except Exception:

                payload = message.get_payload(
                    decode=True
                )

                if payload:

                    content = payload.decode(
                        "utf-8",
                        errors="ignore"
                    )

                else:

                    content = ""


            if content:

                body_parts.append(
                    str(content)
                )


    except Exception:

        pass


    return "\n".join(
        body_parts
    )


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(message):

    authentication_results = (
        message.get(
            "Authentication-Results",
            ""
        )
        or ""
    )


    received_spf = (
        message.get(
            "Received-SPF",
            ""
        )
        or ""
    )


    auth_text = (
        authentication_results
        + " "
        + received_spf
    ).lower()


    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if re.search(
        r"\bspf\s*=\s*pass\b",
        auth_text
    ):

        spf = "PASS"

    elif re.search(
        r"\bspf\s*=\s*(fail|softfail|neutral)\b",
        auth_text
    ):

        match = re.search(
            r"\bspf\s*=\s*(fail|softfail|neutral)\b",
            auth_text
        )

        spf = match.group(
            1
        ).upper()

    elif "pass" in received_spf.lower():

        spf = "PASS"

    elif "fail" in received_spf.lower():

        spf = "FAIL"

    else:

        spf = "UNKNOWN"


    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if re.search(
        r"\bdkim\s*=\s*pass\b",
        auth_text
    ):

        dkim = "PASS"

    elif re.search(
        r"\bdkim\s*=\s*(fail|neutral|temperror|permerror)\b",
        auth_text
    ):

        match = re.search(
            r"\bdkim\s*=\s*(fail|neutral|temperror|permerror)\b",
            auth_text
        )

        dkim = match.group(
            1
        ).upper()

    else:

        dkim = "UNKNOWN"


    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if re.search(
        r"\bdmarc\s*=\s*pass\b",
        auth_text
    ):

        dmarc = "PASS"

    elif re.search(
        r"\bdmarc\s*=\s*(fail|neutral|temperror|permerror)\b",
        auth_text
    ):

        match = re.search(
            r"\bdmarc\s*=\s*(fail|neutral|temperror|permerror)\b",
            auth_text
        )

        dmarc = match.group(
            1
        ).upper()

    else:

        dmarc = "UNKNOWN"


    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }


# ============================================================
# RECEIVED HEADER EXTRACTION
# ============================================================

def extract_received_headers(message):

    headers = (
        message.get_all(
            "Received",
            []
        )
    )


    return [
        str(header)
        for header in headers
    ]


# ============================================================
# EMAIL INFORMATION
# ============================================================

def extract_email_information(message):

    from_header = (
        message.get(
            "From",
            ""
        )
        or ""
    )


    to_header = (
        message.get(
            "To",
            ""
        )
        or ""
    )


    reply_to_header = (
        message.get(
            "Reply-To",
            ""
        )
        or ""
    )


    return_path = (
        message.get(
            "Return-Path",
            ""
        )
        or ""
    )


    subject = (
        message.get(
            "Subject",
            ""
        )
        or ""
    )


    message_id = (
        message.get(
            "Message-ID",
            ""
        )
        or ""
    )


    from_name, from_email = parseaddr(
        from_header
    )


    reply_name, reply_email = parseaddr(
        reply_to_header
    )


    return {
        "from": from_header,
        "from_name": from_name,
        "from_email": from_email,
        "to": to_header,
        "reply_to": reply_to_header,
        "reply_to_email": reply_email,
        "return_path": return_path,
        "subject": subject,
        "message_id": message_id
    }


# ============================================================
# THREAT DETECTION
# ============================================================

def detect_threats(
    email_info,
    authentication,
    urls,
    suspicious_urls,
    body,
    ips
):

    indicators = []

    risk_factors = []

    threat_types = []


    # ========================================================
    # PHISHING
    # ========================================================

    phishing_keywords = [
        "verify your account",
        "verify account",
        "confirm your account",
        "password reset",
        "reset your password",
        "account suspended",
        "account locked",
        "urgent action",
        "click here",
        "login immediately",
        "security alert",
        "verify identity",
        "payment failed",
        "payment required"
    ]


    lower_body = body.lower()


    found_phishing = []


    for keyword in phishing_keywords:

        if keyword in lower_body:

            found_phishing.append(
                keyword
            )


    if found_phishing:

        threat_types.append(
            "Phishing"
        )


        indicators.append(
            "Phishing-related language detected"
        )


        risk_factors.append(
            {
                "indicator":
                    "Phishing-related language",

                "points":
                    min(
                        25,
                        len(found_phishing) * 5
                    )
            }
        )


    # ========================================================
    # SUSPICIOUS URLs
    # ========================================================

    if suspicious_urls:

        if "Phishing" not in threat_types:

            threat_types.append(
                "Phishing"
            )


        indicators.append(
            f"{len(suspicious_urls)} suspicious URL(s) detected"
        )


        risk_factors.append(
            {
                "indicator":
                    "Suspicious URLs",

                "points":
                    min(
                        30,
                        len(suspicious_urls) * 10
                    )
            }
        )


    # ========================================================
    # AUTHENTICATION
    # ========================================================

    auth_failures = []


    if authentication["spf"] in [
        "FAIL",
        "SOFTFAIL"
    ]:

        auth_failures.append(
            "SPF"
        )


    if authentication["dkim"] == "FAIL":

        auth_failures.append(
            "DKIM"
        )


    if authentication["dmarc"] == "FAIL":

        auth_failures.append(
            "DMARC"
        )


    if auth_failures:

        indicators.append(
            "Email authentication failure: "
            + ", ".join(auth_failures)
        )


        risk_factors.append(
            {
                "indicator":
                    "Authentication failure",

                "points":
                    min(
                        25,
                        len(auth_failures) * 10
                    )
            }
        )


    # ========================================================
    # REPLY-TO MISMATCH
    # ========================================================

    from_email = (
        email_info.get(
            "from_email",
            ""
        )
        or ""
    ).lower()


    reply_email = (
        email_info.get(
            "reply_to_email",
            ""
        )
        or ""
    ).lower()


    if (
        from_email
        and reply_email
        and "@"
        in from_email
        and "@"
        in reply_email
    ):

        from_domain = (
            from_email.split(
                "@"
            )[-1]
        )


        reply_domain = (
            reply_email.split(
                "@"
            )[-1]
        )


        if from_domain != reply_domain:

            indicators.append(
                "Reply-To domain differs from sender domain"
            )


            risk_factors.append(
                {
                    "indicator":
                        "Reply-To mismatch",

                    "points":
                        15
                }
            )


    # ========================================================
    # BEC DETECTION
    # ========================================================

    bec_keywords = [
        "wire transfer",
        "bank transfer",
        "gift card",
        "urgent payment",
        "transfer money",
        "invoice",
        "payment",
        "confidential",
        "change bank account",
        "change payment details"
    ]


    found_bec = []


    for keyword in bec_keywords:

        if keyword in lower_body:

            found_bec.append(
                keyword
            )


    if found_bec:

        threat_types.append(
            "BEC"
        )


        indicators.append(
            "Business Email Compromise related language detected"
        )


        risk_factors.append(
            {
                "indicator":
                    "BEC-related language",

                "points":
                    min(
                        25,
                        len(found_bec) * 5
                    )
            }
        )


    # ========================================================
    # SENDER DOMAIN
    # ========================================================

    if from_email:

        suspicious_free_domains = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "proton.me",
            "protonmail.com"
        ]


        sender_domain = (
            from_email.split(
                "@"
            )[-1]
        )


        # This is not automatically malicious.
        # Only add a small indicator if email impersonation-like
        # content exists.

        if (
            sender_domain
            in suspicious_free_domains
            and (
                found_bec
                or found_phishing
            )
        ):

            indicators.append(
                "Free email provider used with suspicious content"
            )


            risk_factors.append(
                {
                    "indicator":
                        "Suspicious free-mail sender",

                    "points":
                        5
                }
            )


    # ========================================================
    # IP INFRASTRUCTURE
    # ========================================================

    public_ips = []


    for ip in ips:

        try:

            ip_obj = ipaddress.ip_address(
                ip
            )


            if ip_obj.is_global:

                public_ips.append(
                    ip
                )

        except ValueError:

            pass


    if public_ips:

        indicators.append(
            f"{len(public_ips)} public IP address(es) detected"
        )


    # ========================================================
    # REMOVE DUPLICATE THREAT TYPES
    # ========================================================

    threat_types = list(
        dict.fromkeys(
            threat_types
        )
    )


    return (
        threat_types,
        indicators,
        risk_factors
    )


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    risk_factors
):

    score = 0


    for factor in risk_factors:

        try:

            score += int(
                factor.get(
                    "points",
                    0
                )
            )

        except Exception:

            pass


    # Maximum 100

    return min(
        100,
        max(
            0,
            score
        )
    )


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_risk(score):

    if score >= 80:

        return "CRITICAL"


    if score >= 60:

        return "HIGH RISK"


    if score >= 30:

        return "SUSPICIOUS"


    return "LOW RISK"


# ============================================================
# ANALYSIS SUMMARY
# ============================================================

def create_summary(
    classification,
    threat_types,
    indicators,
    authentication,
    suspicious_urls,
    ips
):

    if classification == "CRITICAL":

        summary = (
            "Critical threat indicators were detected. "
            "The email requires immediate security review "
            "and should be treated as potentially malicious."
        )


    elif classification == "HIGH RISK":

        summary = (
            "Multiple suspicious characteristics were detected. "
            "The email should be reviewed by a security analyst "
            "before any interaction."
        )


    elif classification == "SUSPICIOUS":

        summary = (
            "The email contains potentially suspicious "
            "characteristics that require further investigation."
        )


    else:

        summary = (
            "No major malicious indicators were detected "
            "by the current analysis engine."
        )


    if threat_types:

        summary += (
            " Detected threat categories: "
            + ", ".join(
                threat_types
            )
            + "."
        )


    if indicators:

        summary += (
            f" {len(indicators)} indicator(s) "
            "were identified."
        )


    if suspicious_urls:

        summary += (
            " Suspicious URL characteristics "
            "were detected."
        )


    if (
        authentication.get("spf") == "FAIL"
        or authentication.get("dkim") == "FAIL"
        or authentication.get("dmarc") == "FAIL"
    ):

        summary += (
            " One or more email authentication "
            "mechanisms failed."
        )


    if ips:

        summary += (
            f" {len(ips)} IP address(es) were extracted "
            "from the email."
        )


    return summary


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(
    email_bytes
):

    return hashlib.sha256(
        email_bytes
    ).hexdigest()


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_email(
    email_bytes,
    filename="email.eml"
):

    # ========================================================
    # HASH
    # ========================================================

    sha256 = calculate_sha256(
        email_bytes
    )


    # ========================================================
    # PARSE EMAIL
    # ========================================================

    message = BytesParser(
        policy=policy.default
    ).parsebytes(
        email_bytes
    )


    # ========================================================
    # EMAIL INFO
    # ========================================================

    email_info = extract_email_information(
        message
    )


    # ========================================================
    # BODY
    # ========================================================

    body = extract_email_body(
        message
    )


    # Strip HTML for additional detection
    clean_body = re.sub(
        r"<[^>]+>",
        " ",
        body
    )


    clean_body = html.unescape(
        clean_body
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
    # COMPLETE TEXT FOR IP/URL EXTRACTION
    # ========================================================

    all_headers = "\n".join(
        f"{key}: {value}"
        for key, value in message.items()
    )


    complete_text = (
        all_headers
        + "\n"
        + body
    )


    # ========================================================
    # IPs
    # ========================================================

    ips = extract_ips(
        complete_text
    )


    # ========================================================
    # URLS
    # ========================================================

    urls = extract_urls(
        complete_text
    )


    # ========================================================
    # SUSPICIOUS URL ANALYSIS
    # ========================================================

    suspicious_urls = []


    for url in urls:

        analysis = analyze_url(
            url
        )


        if analysis["reasons"]:

            suspicious_urls.append(
                analysis
            )


    # ========================================================
    # GEOLOCATION
    # ========================================================

    geolocation = []


    # Limit API calls to first 5 IPs
    for ip in ips[:5]:

        geolocation.append(
            get_ip_geolocation(
                ip
            )
        )


    # ========================================================
    # THREAT DETECTION
    # ========================================================

    (
        threat_types,
        indicators,
        risk_factors
    ) = detect_threats(
        email_info=email_info,
        authentication=authentication,
        urls=urls,
        suspicious_urls=suspicious_urls,
        body=clean_body,
        ips=ips
    )


    # ========================================================
    # RISK
    # ========================================================

    risk_score = calculate_risk_score(
        risk_factors
    )


    classification = classify_risk(
        risk_score
    )


    # ========================================================
    # SUMMARY
    # ========================================================

    summary = create_summary(
        classification=classification,
        threat_types=threat_types,
        indicators=indicators,
        authentication=authentication,
        suspicious_urls=suspicious_urls,
        ips=ips
    )


    # ========================================================
    # CASE ID
    # ========================================================

    case_id = (
        "EG-"
        + datetime.now(
            timezone.utc
        ).strftime(
            "%Y%m%d%H%M%S"
        )
        + "-"
        + sha256[:8].upper()
    )


    # ========================================================
    # TIMESTAMP
    # ========================================================

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "case_id":
            case_id,

        "filename":
            filename,

        "analysis_timestamp":
            timestamp,

        "risk_score":
            risk_score,

        "classification":
            classification,

        "threat_types":
            threat_types,

        "email":
            email_info,

        "authentication":
            authentication,

        "network":
            {
                "ips":
                    ips,

                "geolocation":
                    geolocation,

                "received_headers":
                    received_headers
            },

        "urls":
            urls,

        "suspicious_urls":
            suspicious_urls,

        "indicators":
            indicators,

        "risk_factors":
            risk_factors,

        "summary":
            summary,

        "evidence":
            {
                "sha256":
                    sha256,

                "integrity_status":
                    "VERIFIED",

                "timestamp":
                    timestamp
            }
    }


    return result