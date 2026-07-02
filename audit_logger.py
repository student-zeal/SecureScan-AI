import os
import json
import datetime
import logging

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
AUDIT_LOG_PATH = os.path.join(LOGS_DIR, 'audit.log')
HISTORY_JSON_PATH = os.path.join(LOGS_DIR, 'history.json')

# Ensure the logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Ensure the audit.log file exists
if not os.path.exists(AUDIT_LOG_PATH):
    try:
        with open(AUDIT_LOG_PATH, 'w', encoding='utf-8') as f:
            pass
    except Exception as e:
        print(f"Server Log Error: Failed to initialize audit.log: {str(e)}")

# Ensure history.json exists and is initialized
if not os.path.exists(HISTORY_JSON_PATH):
    try:
        with open(HISTORY_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f, indent=4)
    except Exception as e:
        print(f"Server Log Error: Failed to initialize history.json: {str(e)}")

# Configure Python's logging module for the audit log
audit_logger = logging.getLogger('audit_logger')
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

# Ensure we don't multiply handlers on reload
if not audit_logger.handlers:
    try:
        file_handler = logging.FileHandler(AUDIT_LOG_PATH, encoding='utf-8')
        formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(formatter)
        audit_logger.addHandler(file_handler)
    except Exception as e:
        print(f"Server Log Error: Failed to add file handler to audit_logger: {str(e)}")

def write_audit_log_from_history(history):
    """
    Regenerates the audit.log file completely from the history array
    to keep both files in perfect synchronization.
    """
    try:
        with open(AUDIT_LOG_PATH, 'w', encoding='utf-8') as f:
            for log in history:
                # Format categories list
                categories_lines = []
                if isinstance(log.get('categories_with_counts'), dict):
                    for cat, count in log['categories_with_counts'].items():
                        categories_lines.append(f"{cat} ({count})")
                cat_str = "\n".join(categories_lines) if categories_lines else "None"
                
                # Format compliance frameworks
                compliance_str = "\n".join(log.get('compliance_frameworks', [])) if log.get('compliance_frameworks') else "None"
                
                log_entry_txt = f"""==================================================

Analysis Timestamp
{log.get('timestamp')}

File Name
{log.get('file_name')}

File Type
{log.get('file_type')}

File Size
{log.get('file_size')}

Processing Time
{log.get('processing_time')} seconds

Risk
{log.get('risk_level').upper()} (Score: {log.get('risk_score')})

Sensitive Categories
{cat_str}

Compliance
{compliance_str}

Total Findings
{log.get('total_findings')}

AI Summary
{log.get('ai_summary_status')}

Status
{log.get('status')}

==================================================\n"""
                f.write(log_entry_txt)
    except Exception as e:
        print(f"Server Log Error: Failed to write to audit.log: {str(e)}")

def log_analysis(file_name, file_type, file_size, processing_time, risk_level, risk_score, findings_count, categories_with_counts, compliance_frameworks, ai_summary_status, status):
    """
    Appends audit log records to audit.log and history.json.
    Never stores actual document content, only logs scanning metadata.
    """
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %I:%M %p")
    
    log_entry_json = {
        "timestamp": timestamp_str,
        "file_name": file_name,
        "file_type": file_type,
        "file_size": file_size,
        "processing_time": round(processing_time, 2),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "total_findings": findings_count,
        "categories_count": len(categories_with_counts),
        "categories_with_counts": categories_with_counts,
        "compliance_frameworks": compliance_frameworks,
        "ai_summary_status": ai_summary_status,
        "status": status.upper()
    }
    
    try:
        history = []
        if os.path.exists(HISTORY_JSON_PATH):
            with open(HISTORY_JSON_PATH, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    history = json.loads(content)
                    
        history.append(log_entry_json)
        
        with open(HISTORY_JSON_PATH, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=4)
            
        # Keep audit.log in sync
        write_audit_log_from_history(history)
    except Exception as e:
        print(f"Server Log Error: Failed to log analysis: {str(e)}")

def update_last_summary_status(status="SUCCESS"):
    """
    Updates the AI Summary status of the last logged analysis when it finishes.
    """
    try:
        if os.path.exists(HISTORY_JSON_PATH):
            with open(HISTORY_JSON_PATH, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    history = json.loads(content)
                    if history:
                        history[-1]['ai_summary_status'] = status
                        with open(HISTORY_JSON_PATH, 'w', encoding='utf-8') as f:
                            json.dump(history, f, indent=4)
                        write_audit_log_from_history(history)
    except Exception as e:
        print(f"Server Log Error: Failed to update last summary status: {str(e)}")

def get_history():
    """
    Reads and returns the list of historical analysis runs from history.json.
    """
    try:
        if os.path.exists(HISTORY_JSON_PATH):
            with open(HISTORY_JSON_PATH, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    return json.loads(content)
    except Exception as e:
        print(f"Server Log Error: Failed to read history.json: {str(e)}")
    return []
