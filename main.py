from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from email_analyzer import analyze_email


app = FastAPI(
    title="EmailGuard AI",
    description="AI-powered Email Threat Detection and Forensic Intelligence Platform",
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
    allow_headers=["*"],
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
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


# ============================================================
# EMAIL ANALYSIS
# ============================================================

@app.post("/analyze-email")
async def analyze_email_endpoint(
    file: UploadFile = File(...)
):

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:

        return {
            "error": "No file selected"
        }


    # --------------------------------------------------------
    # Validate extension
    # --------------------------------------------------------

    if not file.filename.lower().endswith(".eml"):

        return {
            "error": "Only .eml files are supported"
        }


    try:

        # ----------------------------------------------------
        # Read file
        # ----------------------------------------------------

        file_data = await file.read()


        if not file_data:

            return {
                "error": "The uploaded .eml file is empty"
            }


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


    except Exception as e:

        print(
            "Email analysis error:",
            str(e)
        )

        return {
            "error": "Email analysis failed",
            "details": str(e)
        }