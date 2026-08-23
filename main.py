from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from email_analyzer import analyze_email
from report_generator import generate_forensic_report

import os
import tempfile
from datetime import datetime


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="EmailGuard AI",
    description="AI-Powered Email Threat Detection and Forensic Intelligence",
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
def root():

    return {
        "status": "online",
        "message": "EmailGuard AI Backend is running",
        "docs": "/docs"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
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
    # Validate file
    # --------------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected."
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
            detail=f"Unable to read email file: {error}"
        )

    if not content:
        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty."
        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    try:

        result = analyze_email(
            content,
            file.filename
        )

    except TypeError:

        # Compatibility if analyzer accepts only bytes
        try:

            result = analyze_email(
                content
            )

        except Exception as error:

            raise HTTPException(
                status_code=500,
                detail=f"Email analysis failed: {error}"
            )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {error}"
        )

    # --------------------------------------------------------
    # Make sure result is dictionary
    # --------------------------------------------------------

    if not isinstance(result, dict):

        raise HTTPException(
            status_code=500,
            detail="Email analyzer returned invalid data."
        )

    # --------------------------------------------------------
    # Ensure filename exists
    # --------------------------------------------------------

    result["filename"] = file.filename

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return result


# ============================================================
# GENERATE FORENSIC REPORT
# ============================================================

@app.post("/analyze-email/report")
async def generate_report(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No email file provided."
        )

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    # --------------------------------------------------------
    # Read uploaded EML
    # --------------------------------------------------------

    try:

        content = await file.read()

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=f"Unable to read email file: {error}"
        )

    if not content:

        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty."
        )

    # --------------------------------------------------------
    # Analyze email again
    # --------------------------------------------------------

    try:

        try:

            result = analyze_email(
                content,
                file.filename
            )

        except TypeError:

            result = analyze_email(
                content
            )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed while generating report: {error}"
        )

    # --------------------------------------------------------
    # Validate analyzer result
    # --------------------------------------------------------

    if not isinstance(result, dict):

        raise HTTPException(
            status_code=500,
            detail="Invalid analysis result."
        )

    result["filename"] = file.filename

    # --------------------------------------------------------
    # Generate unique report filename
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    safe_name = os.path.splitext(
        os.path.basename(file.filename)
    )[0]

    safe_name = "".join(
        character
        if character.isalnum() or character in "-_"
        else "_"
        for character in safe_name
    )

    report_filename = (
        f"EmailGuard_Forensic_Report_"
        f"{safe_name}_"
        f"{timestamp}.pdf"
    )

    # --------------------------------------------------------
    # Save PDF in current project directory
    # NO ADDITIONAL FOLDER
    # --------------------------------------------------------

    report_path = os.path.join(
        os.getcwd(),
        report_filename
    )

    # --------------------------------------------------------
    # Generate PDF
    # --------------------------------------------------------

    try:

        generated_path = generate_forensic_report(
            result,
            report_path
        )

    except Exception as error:

        print(
            "REPORT GENERATION ERROR:",
            repr(error)
        )

        # Remove incomplete PDF if created

        if os.path.exists(report_path):

            try:
                os.remove(report_path)
            except:
                pass

        raise HTTPException(
            status_code=500,
            detail=f"PDF generation failed: {error}"
        )

    # --------------------------------------------------------
    # Check PDF exists
    # --------------------------------------------------------

    if not generated_path:

        raise HTTPException(
            status_code=500,
            detail="PDF generator did not return a file path."
        )

    if not os.path.exists(generated_path):

        raise HTTPException(
            status_code=500,
            detail="PDF file was not created."
        )

    # --------------------------------------------------------
    # Check PDF size
    # --------------------------------------------------------

    if os.path.getsize(generated_path) == 0:

        try:
            os.remove(generated_path)
        except:
            pass

        raise HTTPException(
            status_code=500,
            detail="Generated PDF is empty."
        )

    # --------------------------------------------------------
    # RETURN PDF
    # --------------------------------------------------------

    return FileResponse(
        path=generated_path,
        media_type="application/pdf",
        filename=report_filename,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{report_filename}"'
            )
        }
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )