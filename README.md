# 🔒 SecureScan AI

An AI-powered Sensitive Data Detection & Compliance Assistant that analyzes uploaded documents to detect sensitive information, classify risk levels, generate AI-powered compliance summaries, and answer user queries using Google Gemini AI.

# 🚀 Features

- 📄 Upload PDF, TXT, and CSV documents
- 🔍 Detect sensitive information using Regex
- 🛡️ Risk Classification (Low / Medium / High)
- 🤖 AI-powered Compliance Summary using Google Gemini
- 💬 AI Document Assistant (Question Answering)
- 📊 Interactive Analysis Dashboard
- 📝 Audit Logging
- 📄 Export Reports as PDF and TXT
- 🔒 Sensitive Data Masking


# 🛠️ Tech Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- Flask

### AI
- Google Gemini API
- Gemini 2.5 Flash Model

### Libraries Used
- pdfplumber
- pandas
- reportlab
- python-dotenv
- google-genai
- regex


# ⚙️ Setup Instructions (MANDATORY)

### 1. Clone the Repository

```bash
git clone https://github.com/student-zeal/SecureScan-AI.git
```

### 2. Navigate into the Project

```bash
cd SecureScan-AI
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Create a `.env` File

```env
GEMINI_API_KEY=YOUR_GEMINI_API_KEY
```

### 5. Run the Application

```bash
python app.py
```

### 6. Open the Application

```
http://127.0.0.1:5000
```

# 🏗️ Architecture Overview (MANDATORY)

The application follows a Flask-based client-server architecture.

```
                User
                  │
                  ▼
        Upload Document (PDF/TXT/CSV)
                  │
                  ▼
            Flask Backend
                  │
      ┌───────────┼────────────┐
      │           │            │
      ▼           ▼            ▼
 Text Extraction Regex Detection Risk Analysis
      │           │            │
      └───────────┼────────────┘
                  │
                  ▼
          Audit Logger
                  │
                  ▼
      Google Gemini API
                  │
      ┌───────────┴───────────┐
      ▼                       ▼
 AI Summary            AI Question Answering
                  │
                  ▼
          Dashboard & Reports
```

### Workflow

1. User uploads a PDF, TXT, or CSV document.
2. The backend extracts readable text.
3. Sensitive information is detected using Regex patterns.
4. A weighted risk score is calculated.
5. The document is classified as Low, Medium, or High Risk.
6. Google Gemini generates compliance summaries.
7. Users can interact with the AI assistant to ask document-related questions.
8. Analysis is stored in Audit Logs.
9. Reports can be exported as PDF or TXT.

# 🤖 AI / ML Approach Used 

The application combines rule-based detection with Generative AI.

- Regular Expressions (Regex) are used to detect structured sensitive information such as Aadhaar numbers, PAN numbers, phone numbers, email addresses, API keys, passwords, bank account details, and credit card numbers.

- A weighted risk scoring algorithm classifies documents into Low, Medium, and High Risk based on the detected entities.

- Google Gemini 2.5 Flash is used to:
  - Generate compliance summaries.
  - Explain security risks.
  - Recommend remediation steps.
  - Answer user questions related to the uploaded document.

### Rule-Based Detection

Regular Expressions (Regex) are used to detect:

- Aadhaar Numbers
- PAN Numbers
- Email Addresses
- Phone Numbers
- Credit Card Numbers
- Bank Account Details
- IFSC Codes
- Passwords
- API Keys
- Employee IDs
- IP Addresses

### Risk Classification

A weighted scoring algorithm calculates the overall document risk.

Risk Levels:

- 🟢 Low Risk
- 🟡 Medium Risk
- 🔴 High Risk

### Generative AI

Google Gemini 2.5 Flash is used to:

- Generate compliance summaries
- Explain detected risks
- Suggest remediation steps
- Answer user questions about the uploaded document


# ⚠️ Challenges Faced (MANDATORY)

During development, the following challenges were encountered:

- Extracting readable text consistently from different document formats.
- Designing accurate Regex patterns while minimizing false positives.
- Maintaining document context for AI-powered question answering.
- Integrating Google Gemini API with the Flask backend.
- Managing session data across different application workflows.
- Handling deployment-specific session persistence issues on Render.
- Designing a clean and user-friendly dashboard.


# 🚀 Future Improvements (MANDATORY)

Planned enhancements include:

- OCR support for scanned PDF documents.
- Multi-document analysis.
- Retrieval-Augmented Generation (RAG).
- ChromaDB or FAISS integration.
- Role-based authentication.
- Cloud database for persistent sessions.
- Additional compliance standards such as HIPAA and SOC 2.
- Improved analytics dashboard.
- Real-time collaboration.


# 📄 Supported File Types

- PDF
- TXT
- CSV


# 🔍 Sensitive Information Detected

- Aadhaar Numbers
- PAN Numbers
- Passport Numbers
- Driving License Numbers
- Email Addresses
- Phone Numbers
- Credit Card Numbers
- Bank Account Details
- IFSC Codes
- API Keys
- Passwords
- Employee IDs
- IP Addresses

# 📸 Screenshots

## 🏠 Home Page

![Home](screenshots/homepage.png)


## 📊 Analysis Dashboard

![Dashboard](screenshots/dashboard.png)

## 🤖 AI Assistant

![AI Assistant](screenshots/ai-assistant.png)

## 📝 Audit Logs

![Audit Logs](screenshots/auditlogs.png)


## 📄 Export Report

![Report](screenshots/report.png)


# 🌐 Working Prototype Deployment Link (MANDATORY)

**Live Application**

https://securescan-ai-rx6m.onrender.com


# 📹 Demo Video

https://drive.google.com/file/d/12G2PaAx6nF_wiBg-6PSNHFxca7ukmQn8/view?usp=sharing

# 👨‍💻 Author

**Shruti Kumbhardare**

Information Technology Student


# 📜 License

This project has been developed for educational and internship evaluation purposes only.
