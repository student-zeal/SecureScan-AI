from flask import Flask, request, jsonify, render_template, send_file
import os
import io
import csv
import datetime
import time
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Import utilities from the existing modules
import detector
import file_reader
import ai_engine
import audit_logger

load_dotenv()

app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Limit uploads to 16 MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Allowed extensions
ALLOWED_EXTENSIONS = {'pdf', 'txt', 'csv'}

# In-memory session representation
SESSION = {
    "doc_text": None,
    "findings": None,
    "risk": None,
    "metadata": None,
    "summary_text": None
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Error handler for file size limit exceeded (16MB)
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File size exceeds the maximum limit of 16 MB."}), 413

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    start_time = time.time()
    
    # Validate file presence
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request. Please upload a file."}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected. Please select a valid document."}), 400
        
    # Validate extension
    if not allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type. Only PDF, TXT, and CSV files are allowed."}), 400
        
    # Secure filename and handle empty fallback
    filename = secure_filename(file.filename)
    if not filename:
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'txt'
        filename = f"uploaded_file.{ext}"
        
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    file_type = file.filename.rsplit('.', 1)[1].upper() if '.' in file.filename else 'UNKNOWN'
    try:
        size_bytes = os.path.getsize(filepath)
        if size_bytes < 1024:
            file_size_str = f"{size_bytes} Bytes"
        elif size_bytes < 1024 * 1024:
            file_size_str = f"{size_bytes / 1024:.2f} KB"
        else:
            file_size_str = f"{size_bytes / (1024 * 1024):.2f} MB"
    except Exception:
        file_size_str = "0 Bytes"
        
    try:
        # Extract text from the saved file using Python's file object.
        with open(filepath, 'rb') as f:
            doc_text = file_reader.extract_text(f)
            # Handle empty document
            if not doc_text or not doc_text.strip():
                SESSION['doc_text'] = ""
                SESSION['findings'] = {}
                SESSION['risk'] = {
                    "level": "Low Risk",
                    "score": 0,
                    "reasons": ["No readable text found in the uploaded document."]
                }
                SESSION['summary_text'] = None

                now = datetime.datetime.now()
                SESSION['metadata'] = {
                    "file_name": file.filename,
                    "file_size": file_size_str,
                    "file_type": file_type,
                    "analysis_date": now.strftime("%Y-%m-%d"),
                    "analysis_time": now.strftime("%H:%M:%S"),
                    "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "findings_count": 0,
                    "categories_count": 0
                }

                return jsonify({
                    "findings": {},
                    "risk": SESSION["risk"],
                    "findings_count": 0,
                    "metadata": SESSION["metadata"]
                })
            
        # Detect sensitive data and risk
        findings = detector.detect_sensitive_data(doc_text)
        risk = detector.calculate_risk(findings)

        # Generate timestamps
        now = datetime.datetime.now()
        analysis_date = now.strftime("%Y-%m-%d")
        analysis_time = now.strftime("%H:%M:%S")
        analysis_timestamp = f"{analysis_date} {analysis_time}"

        # Total sensitive instances found
        findings_count = sum(len(items) for items in findings.values())

        # Store original unmasked results in SESSION
        SESSION['doc_text'] = doc_text
        SESSION['findings'] = findings
        SESSION['risk'] = risk
        SESSION['summary_text'] = None # Clear previous summaries
        
        SESSION['metadata'] = {
            "file_name": file.filename,
            "file_size": file_size_str,
            "file_type": file_type,
            "analysis_date": analysis_date,
            "analysis_time": analysis_time,
            "timestamp": analysis_timestamp,
            "findings_count": findings_count,
            "categories_count": len(findings)
        }
        
        processing_time = time.time() - start_time
        
        # Log SUCCESS analysis
        try:
            categories_with_counts = {label: len(items) for label, items in findings.items()}
            compliance_frameworks = []
            if any(c in findings for c in ["Aadhaar Number", "PAN Number", "Email Address", "Phone Number", "Employee ID"]):
                compliance_frameworks.append("GDPR")
            if any(c in findings for c in ["Credit Card Number", "Bank Account Number", "IFSC Code"]):
                compliance_frameworks.append("PCI-DSS")
            if any(c in findings for c in ["Password", "API Key / Secret", "IP Address"]):
                compliance_frameworks.append("ISO 27001")
                
            audit_logger.log_analysis(
                file_name=file.filename,
                file_type=file_type,
                file_size=file_size_str,
                processing_time=processing_time,
                risk_level=risk['level'],
                risk_score=risk['score'],
                findings_count=findings_count,
                categories_with_counts=categories_with_counts,
                compliance_frameworks=compliance_frameworks,
                ai_summary_status='PENDING',
                status='SUCCESS'
            )
        except Exception as log_err:
            print(f"Audit log success trace failed: {log_err}")
            
        # Mask findings before returning to the UI for security
        masked_findings = {}
        for label, items in findings.items():
            masked_findings[label] = [detector.mask_value(item, label) for item in items]

        return jsonify({
            "findings": masked_findings,
            "risk": risk,
            "findings_count": findings_count,
            "metadata": SESSION['metadata']
        })
        
    except ValueError as ve:
        processing_time = time.time() - start_time
        # Log FAILED analysis
        try:
            audit_logger.log_analysis(
                file_name=file.filename,
                file_type=file_type,
                file_size=file_size_str,
                processing_time=processing_time,
                risk_level='N/A',
                risk_score=0,
                findings_count=0,
                categories_with_counts={},
                compliance_frameworks=[],
                ai_summary_status='PENDING',
                status='FAILED'
            )
        except Exception as log_err:
            print(f"Audit log failure trace failed: {log_err}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        processing_time = time.time() - start_time
        # Log FAILED analysis
        try:
            audit_logger.log_analysis(
                file_name=file.filename,
                file_type=file_type,
                file_size=file_size_str,
                processing_time=processing_time,
                risk_level='N/A',
                risk_score=0,
                findings_count=0,
                categories_with_counts={},
                compliance_frameworks=[],
                ai_summary_status='PENDING',
                status='FAILED'
            )
        except Exception as log_err:
            print(f"Audit log failure trace failed: {log_err}")
        return jsonify({"error": f"An error occurred while analyzing the document: {str(e)}"}), 500
    finally:
        # Automatically delete the uploaded file immediately after processing
        if os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass

@app.route('/api/redact', methods=['GET'])
def redact():
    # Validate session data
    if SESSION.get('doc_text') is None:
        return jsonify({"error": "No document has been analyzed yet. Please upload a file first."}), 400
        
    try:
        # Redacts using the original unmasked session findings and text
        redacted_text = detector.redact_text(SESSION['doc_text'], SESSION['findings'])
        return jsonify({"redacted_text": redacted_text})
    except Exception as e:
        return jsonify({"error": f"Failed to redact document: {str(e)}"}), 500

@app.route('/api/summary', methods=['POST'])
def summary():
    # Validate session data
    if SESSION.get('doc_text') is None:
        return jsonify({"error": "No document has been analyzed yet. Please upload a file first."}), 400
    if not SESSION['doc_text'].strip():
        return jsonify({"summary": "The uploaded document is empty or contains no readable text. AI summary was skipped."})
        
    try:
        # Automatically configures using the environment key
        ai_engine.configure_gemini()
        summary_text = ai_engine.generate_summary(
            findings=SESSION['findings'],
            risk=SESSION['risk'],
            doc_text=SESSION['doc_text']
        )
        # Store in session for report downloads
        SESSION['summary_text'] = summary_text
        
        # Update audit log history summary status to SUCCESS
        try:
            audit_logger.update_last_summary_status("SUCCESS")
        except Exception as log_err:
            print(f"Failed to update audit log summary status: {log_err}")
            
        return jsonify({"summary": summary_text})
    except Exception as e:
        # Update audit log history summary status to FAILED
        try:
            audit_logger.update_last_summary_status("FAILED")
        except Exception as log_err:
            print(f"Failed to update audit log summary status: {log_err}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ask', methods=['POST'])
def ask():
    # Validate session data
    if SESSION.get('doc_text') is None:
        return jsonify({"error": "No document has been analyzed yet. Please upload a file first."}), 400
    if not SESSION['doc_text'].strip():
        return jsonify({"answer": "The uploaded document is empty or contains no readable text. Please upload a document with text before asking questions."})
        
    data = request.get_json(silent=True) or {}
    question = data.get('question')
    
    if not question:
        return jsonify({"error": "Please enter a valid question."}), 400
        
    try:
        # Automatically configures using the environment key
        ai_engine.configure_gemini()
        answer_text = ai_engine.answer_question(
            question=question,
            findings=SESSION['findings'],
            risk=SESSION['risk'],
            doc_text=SESSION['doc_text']
        )
        return jsonify({"answer": answer_text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/<string:report_format>', methods=['GET'])
def download_report(report_format):
    if SESSION.get('doc_text') is None or SESSION.get('metadata') is None:
        return jsonify({"error": "No document has been analyzed yet. Please upload a file first."}), 400

    report_format = report_format.lower()
    metadata = SESSION['metadata']
    risk = SESSION['risk']
    summary_text = SESSION.get('summary_text') or "AI Summary report not generated yet."
    
    # Mask findings before writing to report
    masked_findings = {}
    for label, items in SESSION['findings'].items():
        masked_findings[label] = [detector.mask_value(item, label) for item in items]

    filename_base = f"compliance_report_{secure_filename(metadata['file_name'])}"

    if report_format == 'json':
        report_data = {
            "report_timestamp": metadata['timestamp'],
            "file_info": {
                "name": metadata['file_name'],
                "type": metadata['file_type'],
                "size": metadata['file_size']
            },
            "risk_assessment": {
                "overall_risk_level": risk['level'],
                "risk_score": risk['score'],
                "reasons": risk['reasons']
            },
            "detected_categories": list(masked_findings.keys()),
            "masked_sensitive_data": masked_findings,
            "compliance_summary": summary_text
        }
        
        # Serialize directly to bytes
        import json
        json_bytes = json.dumps(report_data, indent=4).encode('utf-8')
        return send_file(
            io.BytesIO(json_bytes),
            mimetype='application/json',
            as_attachment=True,
            download_name=f"{filename_base}.json"
        )

    elif report_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Analysis Timestamp", metadata['timestamp']])
        writer.writerow(["File Name", metadata['file_name']])
        writer.writerow(["File Type", metadata['file_type']])
        writer.writerow(["File Size", metadata['file_size']])
        writer.writerow(["Overall Risk Level", risk['level']])
        writer.writerow(["Risk Score", risk['score']])
        writer.writerow([])
        writer.writerow(["Category", "Masked Sensitive Value"])
        
        if not masked_findings:
            writer.writerow(["None", "No sensitive data detected"])
        else:
            for label, items in masked_findings.items():
                for item in items:
                    writer.writerow([label, item])
                    
        csv_bytes = output.getvalue().encode('utf-8')
        return send_file(
            io.BytesIO(csv_bytes),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"{filename_base}.csv"
        )

    elif report_format == 'txt':
        lines = []
        lines.append("==================================================")
        lines.append("        SENSITIVE DATA ANALYSIS REPORT            ")
        lines.append("==================================================")
        lines.append(f"Analysis Timestamp : {metadata['timestamp']}")
        lines.append(f"Document File Name : {metadata['file_name']}")
        lines.append(f"Document File Type : {metadata['file_type']}")
        lines.append(f"Document File Size : {metadata['file_size']}")
        lines.append("--------------------------------------------------")
        lines.append(f"OVERALL RISK LEVEL : {risk['level'].upper()}")
        lines.append(f"RISK SCORE         : {risk['score']}")
        lines.append("RISK EXPLANATION   :")
        for r in risk['reasons']:
            lines.append(f"  {r}")
        lines.append("--------------------------------------------------")
        lines.append("DETECTED SENSITIVE DATA (MASKED):")
        if not masked_findings:
            lines.append("  No sensitive data detected.")
        else:
            for label, items in masked_findings.items():
                lines.append(f"  * {label} ({len(items)} instance(s)):")
                for item in items:
                    lines.append(f"    - {item}")
        lines.append("--------------------------------------------------")
        lines.append("COMPLIANCE & AI SUMMARY REPORT:")
        lines.append(summary_text)
        lines.append("==================================================")
        
        txt_bytes = "\n".join(lines).encode('utf-8')
        return send_file(
            io.BytesIO(txt_bytes),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{filename_base}.txt"
        )

    elif report_format == 'pdf':
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer, 
                pagesize=letter,
                rightMargin=45, 
                leftMargin=45, 
                topMargin=45, 
                bottomMargin=45
            )
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontSize=18,
                textColor=colors.HexColor('#1e3a8a'),
                spaceAfter=15
            )
            h2_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading2'],
                fontSize=12,
                textColor=colors.HexColor('#1e3a8a'),
                spaceBefore=15,
                spaceAfter=8,
                borderColor=colors.HexColor('#e2e8f0'),
                borderWidth=1,
                borderRadius=2,
                borderPadding=4
            )
            body_style = ParagraphStyle(
                'ReportBody',
                parent=styles['Normal'],
                fontSize=9,
                leading=13,
                textColor=colors.HexColor('#0f172a')
            )
            bold_body_style = ParagraphStyle(
                'BoldReportBody',
                parent=body_style,
                fontName='Helvetica-Bold'
            )
            
            story = []
            
            # Header
            story.append(Paragraph("SENSITIVE DATA ANALYSIS REPORT", title_style))
            story.append(Spacer(1, 5))
            
            # Metadata Table
            table_data = [
                [Paragraph("Analysis Timestamp:", bold_body_style), Paragraph(metadata['timestamp'], body_style)],
                [Paragraph("File Name:", bold_body_style), Paragraph(metadata['file_name'], body_style)],
                [Paragraph("File Type:", bold_body_style), Paragraph(metadata['file_type'], body_style)],
                [Paragraph("File Size:", bold_body_style), Paragraph(metadata['file_size'], body_style)],
                [Paragraph("Overall Risk Level:", bold_body_style), Paragraph(f"<b>{risk['level'].upper()}</b> (Score: {risk['score']})", body_style)]
            ]
            meta_table = Table(table_data, colWidths=[120, 380])
            meta_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#f1f5f9')),
            ]))
            story.append(meta_table)
            
            # Risk Reasons
            story.append(Paragraph("RISK EXPLANATION", h2_style))
            for reason in risk['reasons']:
                story.append(Paragraph(reason, body_style))
                story.append(Spacer(1, 2))
            
            # Detected Sensitive Data
            story.append(Paragraph("DETECTED SENSITIVE DATA (MASKED)", h2_style))
            if not masked_findings:
                story.append(Paragraph("No sensitive data detected.", body_style))
            else:
                for label, items in masked_findings.items():
                    story.append(Paragraph(f"<b>{label} ({len(items)} found):</b>", body_style))
                    story.append(Spacer(1, 2))
                    for item in items:
                        story.append(Paragraph(f"  • {item}", body_style))
                        story.append(Spacer(1, 1))
                    story.append(Spacer(1, 4))
            
            # Compliance summary
            story.append(Paragraph("COMPLIANCE SUMMARY", h2_style))
            summary_para = summary_text.replace('\n', '<br/>')
            story.append(Paragraph(summary_para, body_style))
            
            # Footer text
            story.append(Spacer(1, 20))
            story.append(Paragraph("<i>Disclaimer: This report was generated automatically. All sensitive information has been masked to ensure compliance.</i>", body_style))
            
            doc.build(story)
            buffer.seek(0)
            
            return send_file(
                io.BytesIO(buffer.getvalue()),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"{filename_base}.pdf"
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500

    else:
        return jsonify({"error": "Unsupported report format. Only JSON, CSV, TXT, and PDF reports are supported."}), 400


@app.route('/api/chat/export', methods=['POST'])
def export_chat():
    if SESSION.get('metadata') is None:
        return jsonify({"error": "No document analyzed yet. Please upload a file first."}), 400
        
    data = request.get_json(silent=True) or {}
    report_format = data.get('format', 'txt').lower()
    messages = data.get('messages', [])
    
    if not messages:
        return jsonify({"error": "No chat history to export."}), 400
        
    metadata = SESSION['metadata']
    filename_base = f"chat_history_{secure_filename(metadata['file_name'])}"
    
    if report_format == 'txt':
        lines = []
        lines.append("==================================================")
        lines.append("        AI DOCUMENT ASSISTANT CHAT LOG            ")
        lines.append("==================================================")
        lines.append(f"Document File Name : {metadata['file_name']}")
        lines.append(f"Analysis Timestamp : {metadata['timestamp']}")
        lines.append(f"Exported Timestamp : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("--------------------------------------------------\n")
        
        for msg in messages:
            sender = "USER" if msg.get('sender') == 'user' else "AI ASSISTANT"
            timestamp = msg.get('timestamp', '')
            text = msg.get('text', '')
            lines.append(f"[{timestamp}] {sender}:")
            lines.append(f"{text}")
            lines.append("-" * 50 + "\n")
            
        txt_bytes = "\n".join(lines).encode('utf-8')
        return send_file(
            io.BytesIO(txt_bytes),
            mimetype='text/plain',
            as_attachment=True,
            download_name=f"{filename_base}.txt"
        )
        
    elif report_format == 'pdf':
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer, 
                pagesize=letter,
                rightMargin=45, 
                leftMargin=45, 
                topMargin=45, 
                bottomMargin=45
            )
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle(
                'ChatDocTitle',
                parent=styles['Heading1'],
                fontSize=18,
                textColor=colors.HexColor('#1e3a8a'),
                spaceAfter=15
            )
            meta_style = ParagraphStyle(
                'ChatMetaStyle',
                parent=styles['Normal'],
                fontSize=9,
                textColor=colors.HexColor('#64748b'),
                spaceAfter=10
            )
            user_msg_style = ParagraphStyle(
                'UserMsgStyle',
                parent=styles['Normal'],
                fontSize=9,
                leading=13,
                textColor=colors.HexColor('#1e3a8a')
            )
            ai_msg_style = ParagraphStyle(
                'AiMsgStyle',
                parent=styles['Normal'],
                fontSize=9,
                leading=13,
                textColor=colors.HexColor('#0f172a')
            )
            bold_style = ParagraphStyle(
                'ChatBold',
                parent=styles['Normal'],
                fontName='Helvetica-Bold',
                fontSize=9,
                leading=13
            )
            
            story = []
            
            # Title
            story.append(Paragraph("AI DOCUMENT ASSISTANT CHAT LOG", title_style))
            story.append(Paragraph(f"<b>Document:</b> {metadata['file_name']} | <b>Analyzed:</b> {metadata['timestamp']}", meta_style))
            story.append(Spacer(1, 10))
            
            # Chat flow table
            chat_data = []
            for msg in messages:
                sender_label = "USER" if msg.get('sender') == 'user' else "AI ASSISTANT"
                timestamp = msg.get('timestamp', '')
                text = msg.get('text', '')
                
                # Replace newline formatting in text with HTML line breaks
                formatted_text = text.replace('\n', '<br/>')
                
                sender_p = Paragraph(f"<b>{sender_label}</b><br/><font color='#64748b' size='7'>[{timestamp}]</font>", bold_style)
                text_p = Paragraph(formatted_text, user_msg_style if msg.get('sender') == 'user' else ai_msg_style)
                
                chat_data.append([sender_p, text_p])
                
            chat_table = Table(chat_data, colWidths=[100, 400])
            chat_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
            ]))
            story.append(chat_table)
            
            doc.build(story)
            buffer.seek(0)
            
            return send_file(
                io.BytesIO(buffer.getvalue()),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f"{filename_base}.pdf"
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate PDF chat export: {str(e)}"}), 500
            
    else:
        return jsonify({"error": "Unsupported export format. Supported formats: PDF, TXT."}), 400


@app.route('/api/audit/history', methods=['GET'])
def get_audit_history():
    return jsonify(audit_logger.get_history())


@app.route('/api/audit/download/json', methods=['GET'])
def download_audit_json():
    try:
        current_date = datetime.date.today().strftime("%Y-%m-%d")
        if os.path.exists(audit_logger.HISTORY_JSON_PATH):
            return send_file(
                audit_logger.HISTORY_JSON_PATH,
                mimetype='application/json',
                as_attachment=True,
                download_name=f"Audit_History_{current_date}.json"
            )
        return jsonify({"error": "History file not found."}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to download history JSON: {str(e)}"}), 500


@app.route('/api/audit/download/txt', methods=['GET'])
def download_audit_txt():
    try:
        current_date = datetime.date.today().strftime("%Y-%m-%d")
        if os.path.exists(audit_logger.AUDIT_LOG_PATH):
            return send_file(
                audit_logger.AUDIT_LOG_PATH,
                mimetype='text/plain',
                as_attachment=True,
                download_name=f"Audit_Log_{current_date}.txt"
            )
        return jsonify({"error": "Audit log file not found."}), 404
    except Exception as e:
        return jsonify({"error": f"Failed to download audit TXT: {str(e)}"}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
