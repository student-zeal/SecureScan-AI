🔒 SecureScan AI
SecureScan AI is an AI-powered Sensitive Data Detection & Compliance Assistant built using Flask and Google's Gemini API. It automatically scans documents, detects sensitive information, calculates risk levels, generates AI-powered summaries, and maintains audit logs for compliance reporting.

🚀 Features
- 📄 Upload PDF, TXT and CSV documents
- 🔍 Detect sensitive information using Regex & NLP
- 🛡️ Risk Assessment (Low / Medium / High)
- 🤖 AI-powered Compliance Summary using Gemini AI
- 💬 Interactive AI Document Assistant
- 📊 Analysis Dashboard
- 📁 Export Reports as PDF and TXT
- 📝 Audit Log Management
- 🔒 Data Masking for detected sensitive information

🛠️ Tech Stack
### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Flask
- Python

### AI
- Google Gemini API

### Libraries
- pdfplumber
- python-docx
- pandas
- reportlab
- python-dotenv


📂 Project Structure

SecureScan-AI/
│
├── static/
│   ├── css/
│   └── js/
│
├── templates/
│
├── uploads/
│
├── logs/
│
├── app.py
├── detector.py
├── ai_engine.py
├── audit_logger.py
├── file_reader.py
├── requirements.txt
├── README.md
└── Procfile

## ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/SecureScan-AI.git
```

Go inside the project

```bash
cd SecureScan-AI
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file

```
GEMINI_API_KEY=YOUR_API_KEY
```

Run the application

```bash
python app.py
```

The application will start on

```
http://127.0.0.1:5000
```

 📋 Supported Documents

- PDF
- TXT
- CSV

🔍 Sensitive Information Detected

- Aadhaar Number
- PAN Number
- Passport Number
- Driving License
- Email Address
- Phone Number
- Credit Card Number
- Debit Card Number
- Bank Account Number
- IFSC Code
- API Keys
- Passwords
- Employee IDs
- IP Addresses

📊 Risk Assessment

The application classifies documents into

- 🟢 Low Risk
- 🟡 Medium Risk
- 🔴 High Risk

based on the quantity and severity of detected sensitive information.

🤖 AI Features

- Document Summary
- Compliance Recommendations
- Risk Explanation
- AI Chat Assistant

Powered by the **Google Gemini API **.

📄 Export Options

- PDF Report
- TXT Report

 🌐 Live Demo

Render Deployment:

https://securescan-ai-rx6m.onrender.com


👨‍💻 Author
Shruti Kumbhardare
Information Technology Student

 📜 License

This project is developed for educational and academic purposes.
