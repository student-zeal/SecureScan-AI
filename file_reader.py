"""
File reading utilities: extract raw text from PDF, TXT, CSV
"""

import io
import pandas as pd
import pdfplumber


def read_txt(file) -> str:
    # Try reading as binary stream and decode
    try:
        content = file.read()
        if isinstance(content, bytes):
            return content.decode("utf-8", errors="ignore")
        return str(content)
    except Exception as e:
        raise ValueError(f"Failed to read text file: {str(e)}")


def read_csv(file) -> str:
    # Read binary bytes to allow multiple parse attempts with different encodings
    try:
        content_bytes = file.read()
    except Exception as e:
        raise ValueError(f"Failed to read file stream: {str(e)}")

    # Try UTF-8 first
    try:
        df = pd.read_csv(io.BytesIO(content_bytes), encoding="utf-8")
        return df.to_string(index=False)
    except Exception:
        pass

    # Try latin1 fallback
    try:
        df = pd.read_csv(io.BytesIO(content_bytes), encoding="latin1")
        return df.to_string(index=False)
    except Exception as e:
        # Raise friendly validation error for malformed CSVs
        raise ValueError(
            f"The uploaded CSV is malformed or uses an unsupported encoding. Details: {str(e)}"
        )


def read_pdf(file) -> str:
    text = ""
    try:
        # Seek to 0 just in case
        if hasattr(file, "seek"):
            file.seek(0)
        with pdfplumber.open(file) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        if not text.strip():
            raise ValueError("The PDF contains no readable text (it may be scanned or empty).")
        return text
    except Exception as e:
        raise ValueError(f"Malformed or unreadable PDF: {str(e)}")


def extract_text(uploaded_file) -> str:
    """
    Detects file type by extension and extracts text accordingly.
    Works with both Streamlit's UploadedFile (.name) and Flask's
    FileStorage (.filename) objects.
    """
    name = getattr(uploaded_file, "name", None) or getattr(uploaded_file, "filename", "")
    name = name.lower()

    if name.endswith(".txt"):
        return read_txt(uploaded_file)
    elif name.endswith(".csv"):
        return read_csv(uploaded_file)
    elif name.endswith(".pdf"):
        return read_pdf(uploaded_file)
    else:
        raise ValueError("Unsupported file type. Please upload PDF, TXT, or CSV.")