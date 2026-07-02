"""
AI Engine: uses Google Gemini to generate compliance summaries
and answer user questions about the document.
"""

import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

print("API KEY =", os.getenv("GEMINI_API_KEY"))

client = None


def configure_gemini(api_key: str = None):
    global client
    key = api_key or os.getenv("GEMINI_API_KEY")
    if not key:
        raise Exception("Gemini API Key not found. Please configure the .env file.")
    try:
        client = genai.Client(api_key=key)
    except Exception as e:
        print(f"Server Error Log: Failed to initialize GenAI client: {str(e)}")
        raise Exception("The AI service is temporarily unavailable. Please try again later.")


def get_supported_model(client_instance):
    """
    Dynamically query available models and select a valid Gemini Flash model.
    Falls back to 'gemini-2.5-flash' if dynamic querying fails.
    """
    try:
        available = client_instance.models.list()
        model_names = [m.name for m in available]

        # Print for server logging
        print(f"Server Log: Available models: {model_names}")

        # Clean model names to remove 'models/' prefix if present
        cleaned_names = []
        for name in model_names:
            cleaned = name.replace("models/", "")
            cleaned_names.append(cleaned)

        # Prefer 2.5 flash, then 2.0 flash, then 1.5 flash
        for preferred in ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]:
            if preferred in cleaned_names:
                return preferred

        # Fallback to any gemini flash model found
        for name in cleaned_names:
            if "gemini" in name and "flash" in name:
                return name

        # Fallback if list is empty or doesn't have flash
        if cleaned_names:
            return cleaned_names[0]
    except Exception as e:
        # Log error on server
        print(f"Server Log: Failed to dynamically list models: {str(e)}")

    # Default fallback to latest stable supported model
    return "gemini-2.5-flash"


def generate_summary(findings: dict, risk: dict, doc_text: str) -> str:
    global client
    if not client:
        configure_gemini()

    try:
        # Dynamically determine the best model
        model_name = get_supported_model(client)
        print(f"Server Log: Using Gemini model: {model_name}")

        findings_summary = (
            "\n".join(
                [f"- {label}: {len(items)} instance(s) found" for label, items in findings.items()]
            )
            or "No sensitive data detected."
        )

        prompt = f"""
You are a data compliance and security analyst. A document was scanned for sensitive information.

Findings:
{findings_summary}

Overall Risk Score: {risk['score']}
Risk Level: {risk['level']}

Document excerpt (for context, first 2000 chars):
{doc_text[:2000]}

Write a clear, professional compliance report. You MUST include exactly these section headers:
1. Compliance Observations
2. Security Risks
3. Suggested Remediation
4. Future Recommendations

Keep it concise and practical, use bullet points.
"""
        response = client.models.generate_content(model=model_name, contents=prompt)
        return response.text
    except Exception as e:
        print(f"Server Error Log: Summary generation failed: {str(e)}")
        raise Exception("The AI service is temporarily unavailable. Please try again later.")


def answer_question(question: str, findings: dict, risk: dict, doc_text: str) -> str:
    global client
    if not client:
        configure_gemini()

    try:
        # Dynamically determine the best model
        model_name = get_supported_model(client)
        print(f"Server Log: Using Gemini model: {model_name}")

        findings_summary = (
            "\n".join(
                [
                    f"- {label}: {len(items)} instance(s) -> {items}"
                    for label, items in findings.items()
                ]
            )
            or "No sensitive data detected."
        )

        prompt = f"""
You are a helpful assistant answering questions about a scanned document.

Detected sensitive data:
{findings_summary}

Risk Level: {risk['level']} (score: {risk['score']})

Document content (may be truncated):
{doc_text[:4000]}

User question: {question}

Answer clearly and concisely based on the above information only.
"""
        response = client.models.generate_content(model=model_name, contents=prompt)
        return response.text
    except Exception as e:
        print(f"Server Error Log: Question answering failed: {str(e)}")
        raise Exception("The AI service is temporarily unavailable. Please try again later.")