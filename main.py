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

import os
import tempfile


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="EmailGuard AI",
    description="AI-Powered Email Threat Detection and Forensic Intelligence Platform",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
async def root():

    return {
        "message": "EmailGuard AI Backend is running",
        "status": "online"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "online",
        "service": "EmailGuard AI"
    }


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.post("/analyze-email")
async def analyze_uploaded_email(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename provided."
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    # --------------------------------------------------------
    # Read file
    # --------------------------------------------------------

    try:

        content = await file.read()

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=f"Unable to read file: {error}"
        )

    # --------------------------------------------------------
    # Empty file
    # --------------------------------------------------------

    if not content:

        raise HTTPException(
            status_code=400,
            detail="Uploaded email file is empty."
        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    try:

        result = analyze_email(
            content,
            file.filename
        )

        return result

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
async def generate_report(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename provided."
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    # --------------------------------------------------------
    # Read EML
    # --------------------------------------------------------

    try:

        content = await file.read()

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=f"Unable to read email: {error}"
        )

    if not content:

        raise HTTPException(
            status_code=400,
            detail="Uploaded email file is empty."
        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    try:

        result = analyze_email(
            content,
            file.filename
        )

    except Exception as error:

        print(
            "Report analysis error:",
            error
        )

        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    # --------------------------------------------------------
    # Temporary PDF
    # --------------------------------------------------------

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".pdf"
    )

    output_path = temp_file.name

    temp_file.close()

    # --------------------------------------------------------
    # Generate PDF
    # --------------------------------------------------------

    try:

        generate_forensic_report(
            result,
            output_path
        )

    except Exception as error:

        print(
            "PDF generation error:",
            error
        )

        if os.path.exists(output_path):

            os.remove(
                output_path
            )

        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {error}"
        )

    # --------------------------------------------------------
    # Filename
    # --------------------------------------------------------

    pdf_filename = (
        "EmailGuard_Forensic_Report_"
        + result.get(
            "case_id",
            "Report"
        )
        + ".pdf"
    )

    # --------------------------------------------------------
    # Return PDF
    # --------------------------------------------------------

    return FileResponse(
        path=output_path,
        media_type="application/pdf",
        filename=pdf_filename,
        background=None
    )


# ============================================================
# RUN LOCALLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                8000
            )
        ),
        reload=False
    )