from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException
)

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from email_analyzer import analyze_email
from report_generator import generate_forensic_report

from datetime import datetime
import os


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="EmailGuard AI",
    description=(
        "AI-powered Email Threat Detection "
        "and Forensic Intelligence Platform"
    ),
    version="1.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=["*"],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"]
)


# ============================================================
# DIRECTORIES
# ============================================================

REPORTS_DIR = "reports"

UPLOADS_DIR = "uploads"


os.makedirs(
    REPORTS_DIR,
    exist_ok=True
)

os.makedirs(
    UPLOADS_DIR,
    exist_ok=True
)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "message": "EmailGuard AI Backend is running",
        "status": "online"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.post("/analyze-email")
async def analyze_email_endpoint(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )

    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    try:

        # ----------------------------------------------------
        # Read uploaded file
        # ----------------------------------------------------

        file_data = await file.read()

        if not file_data:

            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty"
            )

        # ----------------------------------------------------
        # Analyze email
        # ----------------------------------------------------

        result = analyze_email(
            file_data
        )

        # ----------------------------------------------------
        # Add filename
        # ----------------------------------------------------

        result["filename"] = file.filename

        return result

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Analysis error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# ANALYZE + GENERATE PDF REPORT
# ============================================================

@app.post("/analyze-email/report")
async def analyze_email_report(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )

    # --------------------------------------------------------
    # Validate .eml
    # --------------------------------------------------------

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    try:

        # ----------------------------------------------------
        # Read file
        # ----------------------------------------------------

        file_data = await file.read()

        if not file_data:

            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty"
            )

        # ----------------------------------------------------
        # Analyze
        # ----------------------------------------------------

        result = analyze_email(
            file_data
        )

        result["filename"] = file.filename

        # ----------------------------------------------------
        # Case ID
        # ----------------------------------------------------

        case_id = result.get(
            "case_id"
        )

        if not case_id:

            case_id = (
                "EM-"
                +
                datetime.now().strftime(
                    "%Y%m%d%H%M%S"
                )
            )

            result["case_id"] = case_id

        # ----------------------------------------------------
        # Generate filename
        # ----------------------------------------------------

        pdf_filename = (
            f"EmailGuard_Forensic_Report_"
            f"{case_id}.pdf"
        )

        pdf_path = os.path.join(
            REPORTS_DIR,
            pdf_filename
        )

        # ----------------------------------------------------
        # Generate PDF
        # ----------------------------------------------------

        generate_forensic_report(
            result,
            pdf_path
        )

        # ----------------------------------------------------
        # Verify PDF
        # ----------------------------------------------------

        if not os.path.exists(pdf_path):

            raise HTTPException(
                status_code=500,
                detail="PDF report was not generated"
            )

        # ----------------------------------------------------
        # Return PDF
        # ----------------------------------------------------

        return FileResponse(
            path=pdf_path,

            media_type="application/pdf",

            filename=pdf_filename,

            headers={
                "Content-Disposition":
                    f'attachment; filename="{pdf_filename}"'
            }
        )

    except HTTPException:

        raise

    except Exception as error:

        print(
            "Report generation error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )


# ============================================================
# GENERATE REPORT FROM JSON
# ============================================================

@app.post("/generate-report")
async def generate_report_from_json(
    data: dict
):

    try:

        # ----------------------------------------------------
        # Case ID
        # ----------------------------------------------------

        case_id = data.get(
            "case_id"
        )

        if not case_id:

            case_id = (
                "EM-"
                +
                datetime.now().strftime(
                    "%Y%m%d%H%M%S"
                )
            )

            data["case_id"] = case_id

        # ----------------------------------------------------
        # Generate filename
        # ----------------------------------------------------

        pdf_filename = (
            f"EmailGuard_Forensic_Report_"
            f"{case_id}.pdf"
        )

        pdf_path = os.path.join(
            REPORTS_DIR,
            pdf_filename
        )

        # ----------------------------------------------------
        # Generate
        # ----------------------------------------------------

        generate_forensic_report(
            data,
            pdf_path
        )

        # ----------------------------------------------------
        # Verify
        # ----------------------------------------------------

        if not os.path.exists(pdf_path):

            raise HTTPException(
                status_code=500,
                detail="PDF report generation failed"
            )

        # ----------------------------------------------------
        # Return
        # ----------------------------------------------------

        return FileResponse(
            path=pdf_path,

            media_type="application/pdf",

            filename=pdf_filename
        )

    except HTTPException:

        raise

    except Exception as error:

        print(
            "JSON report error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )