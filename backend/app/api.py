from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import tempfile
import os
import logging

from app.parsers.email_parser import parse_eml
from app.analyzers.detection_engine import analyze_email


# ============================================================
# PhishLens API
# ============================================================

app = FastAPI(
    title="PhishLens API",
    description="Phishing Email Analysis API",
    version="1.0.0",
)


# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger("phishlens")


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
# UPLOAD LIMIT
# ============================================================

MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_CHUNK_SIZE = 1024 * 1024      # 1 MB


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "application": "PhishLens",
        "status": "online",
        "message": "PhishLens API is running",
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
# EMAIL ANALYSIS ENDPOINT
# ============================================================

@app.post("/analyze")
async def analyze_uploaded_email(
    file: UploadFile = File(...)
):
    """
    Upload an .eml file and analyze it for phishing indicators.
    """

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected"
        )

    # --------------------------------------------------------
    # Validate file extension
    # --------------------------------------------------------

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    temp_path = None
    total_size = 0

    try:

        # ----------------------------------------------------
        # Create temporary .eml file
        # ----------------------------------------------------

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".eml",
            delete=False
        ) as temp_file:

            temp_path = temp_file.name

            # ------------------------------------------------
            # Read upload in chunks
            # ------------------------------------------------

            while True:

                chunk = await file.read(
                    UPLOAD_CHUNK_SIZE
                )

                if not chunk:
                    break

                total_size += len(chunk)

                # --------------------------------------------
                # Enforce upload size limit
                # --------------------------------------------

                if total_size > MAX_UPLOAD_SIZE:

                    raise HTTPException(
                        status_code=413,
                        detail="Uploaded file exceeds the 10 MB size limit"
                    )

                temp_file.write(chunk)

        # ----------------------------------------------------
        # Validate empty file
        # ----------------------------------------------------

        if total_size == 0:

            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty"
            )

        # ----------------------------------------------------
        # Parse email
        # ----------------------------------------------------

        parsed_email = parse_eml(temp_path)

        # ----------------------------------------------------
        # Analyze email
        # ----------------------------------------------------

        results = analyze_email(parsed_email)

        # ----------------------------------------------------
        # Return complete analysis response
        # ----------------------------------------------------

        return {
            "filename": file.filename,

            "status": "analyzed",

            # =================================================
            # EMAIL OVERVIEW
            # =================================================

            "email": {
                "from": parsed_email.get("from"),
                "to": parsed_email.get("to"),
                "reply_to": parsed_email.get("reply_to"),
                "return_path": parsed_email.get("return_path"),
                "subject": parsed_email.get("subject"),
                "date": parsed_email.get("date"),
                "message_id": parsed_email.get("message_id"),
            },

            # =================================================
            # ANALYSIS RESULTS
            # =================================================

            "results": results,
        }

    # --------------------------------------------------------
    # Re-raise our own HTTP errors
    # --------------------------------------------------------

    except HTTPException:
        raise

    # --------------------------------------------------------
    # Handle unexpected errors safely
    # --------------------------------------------------------

    except Exception:

        logger.exception(
            "Unexpected error while analyzing uploaded email"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to analyze the uploaded email"
        )

    # --------------------------------------------------------
    # Always remove temporary file
    # --------------------------------------------------------

    finally:

        if temp_path and os.path.exists(temp_path):

            try:
                os.remove(temp_path)

            except Exception:

                logger.exception(
                    "Unable to remove temporary file"
                )

        try:
            await file.close()

        except Exception:

            logger.exception(
                "Unable to close uploaded file"
            )
