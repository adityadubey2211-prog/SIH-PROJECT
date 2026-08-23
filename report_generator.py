from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from datetime import datetime
import os
import html


# ============================================================
# HELPER
# ============================================================

def safe_text(value):
    """
    Safely convert any value to string and escape HTML
    characters before sending it to ReportLab Paragraph.
    """

    if value is None:
        return "N/A"

    return html.escape(str(value))


# ============================================================
# PAGE FOOTER
# ============================================================

def add_page_footer(canvas, document):
    """
    Adds footer to every PDF page.
    """

    canvas.saveState()

    width, height = A4

    # Footer line
    canvas.setStrokeColor(
        colors.HexColor("#D1D5DB")
    )

    canvas.line(
        18 * mm,
        12 * mm,
        width - 18 * mm,
        12 * mm
    )

    # Footer text
    canvas.setFont(
        "Helvetica",
        7
    )

    canvas.setFillColor(
        colors.HexColor("#6B7280")
    )

    canvas.drawString(
        18 * mm,
        7 * mm,
        "EmailGuard AI - Email Forensic Intelligence Report"
    )

    canvas.drawRightString(
        width - 18 * mm,
        7 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# ============================================================
# TWO COLUMN TABLE
# ============================================================

def create_two_column_table(
    rows,
    normal_style,
    small_style
):
    """
    Creates a standard forensic information table.
    """

    data = []

    for key, value in rows:

        data.append(
            [
                Paragraph(
                    f"<b>{safe_text(key)}</b>",
                    normal_style
                ),

                Paragraph(
                    safe_text(value),
                    small_style
                )
            ]
        )

    table = Table(
        data,
        colWidths=[
            45 * mm,
            125 * mm
        ]
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1")
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F1F5F9")
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ]
        )
    )

    return table


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_forensic_report(
    result,
    output_path
):
    """
    Generate complete EmailGuard AI forensic PDF report.

    Parameters
    ----------
    result : dict
        Analysis result returned by EmailGuard backend.

    output_path : str
        Location where PDF should be created.

    Returns
    -------
    str
        Generated PDF path.
    """

    # ========================================================
    # EXTRACT MAIN DATA
    # ========================================================

    case_id = result.get(
        "case_id",
        "N/A"
    )

    filename = result.get(
        "filename",
        "Unknown"
    )

    timestamp = result.get(
        "analysis_timestamp",
        datetime.now().isoformat()
    )

    risk_score = result.get(
        "risk_score",
        0
    )

    classification = result.get(
        "classification",
        "UNKNOWN"
    )

    threat_types = result.get(
        "threat_types",
        []
    )

    email = result.get(
        "email",
        {}
    )

    authentication = result.get(
        "authentication",
        {}
    )

    network = result.get(
        "network",
        {}
    )

    urls = result.get(
        "urls",
        []
    )

    suspicious_urls = result.get(
        "suspicious_urls",
        []
    )

    indicators = result.get(
        "indicators",
        []
    )

    risk_factors = result.get(
        "risk_factors",
        []
    )

    evidence = result.get(
        "evidence",
        {}
    )

    # ========================================================
    # ENSURE OUTPUT DIRECTORY EXISTS
    # ========================================================

    directory = os.path.dirname(
        output_path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    # ========================================================
    # CREATE PDF DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,

        rightMargin=18 * mm,
        leftMargin=18 * mm,

        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title_style = ParagraphStyle(
        "ReportTitle",

        parent=styles["Title"],

        fontName="Helvetica-Bold",

        fontSize=22,

        leading=26,

        alignment=TA_CENTER,

        textColor=colors.HexColor(
            "#0F172A"
        ),

        spaceAfter=6
    )

    # --------------------------------------------------------
    # SUBTITLE
    # --------------------------------------------------------

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=9,

        leading=13,

        alignment=TA_CENTER,

        textColor=colors.HexColor(
            "#64748B"
        ),

        spaceAfter=15
    )

    # --------------------------------------------------------
    # SECTION HEADING
    # --------------------------------------------------------

    heading_style = ParagraphStyle(
        "ReportHeading",

        parent=styles["Heading2"],

        fontName="Helvetica-Bold",

        fontSize=13,

        leading=17,

        textColor=colors.HexColor(
            "#0F172A"
        ),

        spaceBefore=12,

        spaceAfter=7
    )

    # --------------------------------------------------------
    # NORMAL TEXT
    # --------------------------------------------------------

    normal_style = ParagraphStyle(
        "ReportNormal",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=9,

        leading=13,

        textColor=colors.HexColor(
            "#1E293B"
        )
    )

    # --------------------------------------------------------
    # SMALL TEXT
    # --------------------------------------------------------

    small_style = ParagraphStyle(
        "ReportSmall",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=8,

        leading=11,

        textColor=colors.HexColor(
            "#334155"
        )
    )

    # --------------------------------------------------------
    # DANGER
    # --------------------------------------------------------

    danger_style = ParagraphStyle(
        "Danger",

        parent=normal_style,

        fontName="Helvetica-Bold",

        fontSize=10,

        textColor=colors.HexColor(
            "#B91C1C"
        )
    )

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    success_style = ParagraphStyle(
        "Success",

        parent=normal_style,

        fontName="Helvetica-Bold",

        fontSize=10,

        textColor=colors.HexColor(
            "#15803D"
        )
    )

    # ========================================================
    # STORY
    # ========================================================

    story = []

    # ========================================================
    # REPORT HEADER
    # ========================================================

    story.append(
        Paragraph(
            "EMAILGUARD AI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "EMAIL FORENSIC INTELLIGENCE REPORT",
            subtitle_style
        )
    )

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "EXECUTIVE SUMMARY",
            heading_style
        )
    )

    if risk_score >= 80:

        summary = (
            "CRITICAL THREAT DETECTED. The analyzed email "
            "contains multiple indicators associated with "
            "phishing, business email compromise, impersonation, "
            "suspicious URLs and failed email authentication."
        )

        summary_style = danger_style

    elif risk_score >= 60:

        summary = (
            "HIGH RISK EMAIL. Multiple suspicious "
            "characteristics were detected and analyst "
            "review is recommended."
        )

        summary_style = danger_style

    elif risk_score >= 30:

        summary = (
            "SUSPICIOUS EMAIL. Some potentially malicious "
            "characteristics were identified."
        )

        summary_style = normal_style

    else:

        summary = (
            "LOW RISK. No major malicious indicators were "
            "detected by the current analysis engine."
        )

        summary_style = success_style

    story.append(
        Paragraph(
            safe_text(summary),
            summary_style
        )
    )

    story.append(
        Spacer(
            1,
            8
        )
    )

    # ========================================================
    # 1. CASE INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "1. CASE INFORMATION",
            heading_style
        )
    )

    case_rows = [
        (
            "Case ID",
            case_id
        ),

        (
            "File Name",
            filename
        ),

        (
            "Analysis Timestamp",
            timestamp
        )
    ]

    story.append(
        create_two_column_table(
            case_rows,
            normal_style,
            small_style
        )
    )

    # ========================================================
    # 2. RISK ASSESSMENT
    # ========================================================

    story.append(
        Paragraph(
            "2. RISK ASSESSMENT",
            heading_style
        )
    )

    threat_string = (
        ", ".join(
            str(x)
            for x in threat_types
        )
        if threat_types
        else "None identified"
    )

    risk_rows = [
        (
            "Risk Score",
            f"{risk_score} / 100"
        ),

        (
            "Classification",
            classification
        ),

        (
            "Threat Types",
            threat_string
        )
    ]

    story.append(
        create_two_column_table(
            risk_rows,
            normal_style,
            small_style
        )
    )

    # ========================================================
    # 3. EMAIL INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "3. EMAIL INFORMATION",
            heading_style
        )
    )

    email_rows = [
        (
            "From",
            email.get(
                "from",
                "N/A"
            )
        ),

        (
            "From Email",
            email.get(
                "from_email",
                "N/A"
            )
        ),

        (
            "To",
            email.get(
                "to",
                "N/A"
            )
        ),

        (
            "Reply-To",
            email.get(
                "reply_to",
                "N/A"
            )
        ),

        (
            "Reply-To Email",
            email.get(
                "reply_to_email",
                "N/A"
            )
        ),

        (
            "Return-Path",
            email.get(
                "return_path",
                "N/A"
            )
        ),

        (
            "Subject",
            email.get(
                "subject",
                "N/A"
            )
        ),

        (
            "Message-ID",
            email.get(
                "message_id",
                "N/A"
            )
        )
    ]

    story.append(
        create_two_column_table(
            email_rows,
            normal_style,
            small_style
        )
    )

    # ========================================================
    # 4. EMAIL AUTHENTICATION
    # ========================================================

    story.append(
        Paragraph(
            "4. EMAIL AUTHENTICATION",
            heading_style
        )
    )

    auth_data = [
        [
            Paragraph(
                "<b>Mechanism</b>",
                normal_style
            ),

            Paragraph(
                "<b>Result</b>",
                normal_style
            )
        ],

        [
            Paragraph(
                "SPF",
                normal_style
            ),

            Paragraph(
                safe_text(
                    authentication.get(
                        "spf",
                        "UNKNOWN"
                    )
                ),
                normal_style
            )
        ],

        [
            Paragraph(
                "DKIM",
                normal_style
            ),

            Paragraph(
                safe_text(
                    authentication.get(
                        "dkim",
                        "UNKNOWN"
                    )
                ),
                normal_style
            )
        ],

        [
            Paragraph(
                "DMARC",
                normal_style
            ),

            Paragraph(
                safe_text(
                    authentication.get(
                        "dmarc",
                        "UNKNOWN"
                    )
                ),
                normal_style
            )
        ]
    ]

    auth_table = Table(
        auth_data,

        colWidths=[
            85 * mm,
            85 * mm
        ]
    )

    auth_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#CBD5E1")
                ),

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E2E8F0")
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "ALIGN",
                    (1, 1),
                    (1, -1),
                    "CENTER"
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7
                )
            ]
        )
    )

    story.append(
        auth_table
    )

    # ========================================================
    # 5. NETWORK ANALYSIS
    # ========================================================

    story.append(
        Paragraph(
            "5. NETWORK AND ORIGIN ANALYSIS",
            heading_style
        )
    )

    ips = network.get(
        "ips",
        []
    )

    if ips:

        ip_string = ", ".join(
            str(ip)
            for ip in ips
        )

    else:

        ip_string = (
            "No IP addresses detected"
        )

    network_rows = [
        (
            "Extracted IPs",
            ip_string
        )
    ]

    geolocation = network.get(
        "geolocation",
        []
    )

    for location in geolocation:

        network_rows.extend(
            [
                (
                    "IP Address",
                    location.get(
                        "ip",
                        "N/A"
                    )
                ),

                (
                    "Country",
                    location.get(
                        "country",
                        "Unknown"
                    )
                ),

                (
                    "Region",
                    location.get(
                        "region",
                        "Unknown"
                    )
                ),

                (
                    "City",
                    location.get(
                        "city",
                        "Unknown"
                    )
                ),

                (
                    "ISP",
                    location.get(
                        "isp",
                        "Unknown"
                    )
                ),

                (
                    "Organization",
                    location.get(
                        "organization",
                        "Unknown"
                    )
                ),

                (
                    "Latitude",
                    location.get(
                        "latitude",
                        "N/A"
                    )
                ),

                (
                    "Longitude",
                    location.get(
                        "longitude",
                        "N/A"
                    )
                ),

                (
                    "Lookup Status",
                    location.get(
                        "status",
                        "UNKNOWN"
                    )
                )
            ]
        )

    story.append(
        create_two_column_table(
            network_rows,
            normal_style,
            small_style
        )
    )

    # ========================================================
    # RECEIVED HEADERS
    # ========================================================

    received_headers = network.get(
        "received_headers",
        []
    )

    if received_headers:

        story.append(
            Paragraph(
                "Received Header Chain",
                heading_style
            )
        )

        for index, header in enumerate(
            received_headers,
            start=1
        ):

            story.append(
                Paragraph(
                    f"<b>Hop {index}:</b> "
                    f"{safe_text(header)}",
                    small_style
                )
            )

            story.append(
                Spacer(
                    1,
                    4
                )
            )

    # ========================================================
    # 6. URL ANALYSIS
    # ========================================================

    story.append(
        Paragraph(
            "6. URL ANALYSIS",
            heading_style
        )
    )

    if urls:

        for index, url in enumerate(
            urls,
            start=1
        ):

            story.append(
                Paragraph(
                    f"<b>URL {index}:</b> "
                    f"{safe_text(url)}",
                    small_style
                )
            )

            story.append(
                Spacer(
                    1,
                    4
                )
            )

    else:

        story.append(
            Paragraph(
                "No URLs detected.",
                normal_style
            )
        )

    # ========================================================
    # SUSPICIOUS URLS
    # ========================================================

    if suspicious_urls:

        story.append(
            Paragraph(
                "Suspicious URLs",
                heading_style
            )
        )

        for item in suspicious_urls:

            url = item.get(
                "url",
                "N/A"
            )

            domain = item.get(
                "domain",
                "N/A"
            )

            reasons = item.get(
                "reasons",
                []
            )

            story.append(
                Paragraph(
                    f"<b>URL:</b> "
                    f"{safe_text(url)}",
                    danger_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Domain:</b> "
                    f"{safe_text(domain)}",
                    small_style
                )
            )

            for reason in reasons:

                story.append(
                    Paragraph(
                        f"• {safe_text(reason)}",
                        small_style
                    )
                )

            story.append(
                Spacer(
                    1,
                    7
                )
            )

    # ========================================================
    # 7. THREAT INDICATORS
    # ========================================================

    story.append(
        Paragraph(
            "7. THREAT INDICATORS",
            heading_style
        )
    )

    if indicators:

        for indicator in indicators:

            story.append(
                Paragraph(
                    f"• {safe_text(indicator)}",
                    normal_style
                )
            )

            story.append(
                Spacer(
                    1,
                    3
                )
            )

    else:

        story.append(
            Paragraph(
                "No major indicators detected.",
                normal_style
            )
        )

    # ========================================================
    # 8. RISK FACTORS
    # ========================================================

    story.append(
        Paragraph(
            "8. RISK FACTOR BREAKDOWN",
            heading_style
        )
    )

    if risk_factors:

        factor_data = [
            [
                Paragraph(
                    "<b>Indicator</b>",
                    normal_style
                ),

                Paragraph(
                    "<b>Points</b>",
                    normal_style
                )
            ]
        ]

        for factor in risk_factors:

            factor_data.append(
                [
                    Paragraph(
                        safe_text(
                            factor.get(
                                "indicator",
                                "Unknown"
                            )
                        ),
                        small_style
                    ),

                    Paragraph(
                        safe_text(
                            factor.get(
                                "points",
                                0
                            )
                        ),
                        normal_style
                    )
                ]
            )

        factor_table = Table(
            factor_data,

            colWidths=[
                130 * mm,
                40 * mm
            ],

            repeatRows=1
        )

        factor_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.HexColor("#CBD5E1")
                    ),

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#E2E8F0")
                    ),

                    (
                        "ALIGN",
                        (1, 1),
                        (1, -1),
                        "CENTER"
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE"
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6
                    )
                ]
            )
        )

        story.append(
            factor_table
        )

    else:

        story.append(
            Paragraph(
                "No risk factors recorded.",
                normal_style
            )
        )

    # ========================================================
    # 9. FORENSIC ASSESSMENT
    # ========================================================

    story.append(
        Paragraph(
            "9. FORENSIC ASSESSMENT",
            heading_style
        )
    )

    if risk_score >= 80:

        assessment = (
            "The analyzed email exhibits multiple high-risk "
            "indicators consistent with phishing, impersonation "
            "or business email compromise. Immediate security "
            "review and containment is recommended."
        )

    elif risk_score >= 60:

        assessment = (
            "The analyzed email contains several suspicious "
            "characteristics. Further investigation by a "
            "security analyst is recommended before user "
            "interaction."
        )

    elif risk_score >= 30:

        assessment = (
            "The analyzed email contains some suspicious "
            "characteristics but does not currently meet "
            "the highest risk threshold."
        )

    else:

        assessment = (
            "No major malicious indicators were detected "
            "by the current analysis engine."
        )

    story.append(
        Paragraph(
            safe_text(assessment),
            normal_style
        )
    )

    story.append(
        Spacer(
            1,
            8
        )
    )

    story.append(
        Paragraph(
            "<b>Important:</b> Geolocation results identify "
            "the approximate location of observed network "
            "infrastructure. They do not establish the physical "
            "location or identity of the human attacker.",
            small_style
        )
    )

    # ========================================================
    # 10. DIGITAL EVIDENCE
    # ========================================================

    story.append(
        Paragraph(
            "10. DIGITAL EVIDENCE",
            heading_style
        )
    )

    evidence_rows = [
        (
            "SHA-256",
            evidence.get(
                "sha256",
                "N/A"
            )
        ),

        (
            "Integrity Status",
            evidence.get(
                "integrity_status",
                "N/A"
            )
        ),

        (
            "Evidence Timestamp",
            evidence.get(
                "timestamp",
                "N/A"
            )
        )
    ]

    story.append(
        create_two_column_table(
            evidence_rows,
            normal_style,
            small_style
        )
    )

    # ========================================================
    # 11. RECOMMENDED ACTION
    # ========================================================

    story.append(
        Paragraph(
            "11. RECOMMENDED ACTION",
            heading_style
        )
    )

    if risk_score >= 80:

        actions = [
            "Do not click links contained in the email.",

            "Do not reply to the sender.",

            "Quarantine the email.",

            "Block or investigate suspicious sender domains.",

            "Investigate the originating IP and infrastructure.",

            "Verify the request through an independent trusted channel."
        ]

    elif risk_score >= 60:

        actions = [
            "Avoid interacting with suspicious links or attachments.",

            "Verify the sender through an independent channel.",

            "Forward the email to the security team for investigation."
        ]

    else:

        actions = [
            "Continue normal security monitoring.",

            "Review suspicious indicators if user interaction is planned."
        ]

    for action in actions:

        story.append(
            Paragraph(
                f"• {safe_text(action)}",
                normal_style
            )
        )

        story.append(
            Spacer(
                1,
                3
            )
        )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Spacer(
            1,
            12
        )
    )

    story.append(
        Paragraph(
            "DISCLAIMER",
            heading_style
        )
    )

    disclaimer = (
        "This report is automatically generated by EmailGuard AI "
        "for cybersecurity analysis and investigative support. "
        "The findings represent technical indicators and "
        "confidence-based assessments. They should not be treated "
        "as definitive identification of an individual attacker. "
        "Human analyst review is recommended before legal, "
        "administrative or enforcement action."
    )

    story.append(
        Paragraph(
            safe_text(disclaimer),
            small_style
        )
    )

    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story,

        onFirstPage=add_page_footer,

        onLaterPages=add_page_footer
    )

    return output_path