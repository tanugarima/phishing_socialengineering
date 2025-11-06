import streamlit as st
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import imaplib
import email
import os
import json
from ollama import Client
from dotenv import load_dotenv
import email.policy
import time
import threading
from pymongo import MongoClient
from datetime import datetime, timedelta
import bcrypt
import speech_recognition as sr
import requests
import zipfile
import io
from queue import Queue, Empty
import html
import io as _io
import wave as _wave
import struct as _struct
import math as _math

load_dotenv()
default_email = os.getenv("EMAIL_USER", "")
default_pass = os.getenv("EMAIL_PASS", "")

ollama_client = Client(host='http://localhost:11434')

mongo_client = MongoClient("mongodb+srv://tanugarima712_db_user:4IMjrho5gk4cACtH@emailpass.9uc3vx6.mongodb.net/?retryWrites=true&w=majority&appName=EmailPass")
db = mongo_client["phishing_detector"]
credentials_collection = db["credentials"]
email_checks_collection = db["email_checks"]
processed_emails_collection = db["processed_emails"]

if 'message_queue' not in st.session_state:
    st.session_state.message_queue = Queue()

if 'monitoring_active' not in st.session_state:
    st.session_state.monitoring_active = False
if 'monitor_thread' not in st.session_state:
    st.session_state.monitor_thread = None
if 'last_ui_update' not in st.session_state:
    st.session_state.last_ui_update = datetime.now()
if 'monitoring_messages' not in st.session_state:
    st.session_state.monitoring_messages = []
if 'last_check_time' not in st.session_state:
    st.session_state.last_check_time = None

def mock_phishing_analysis(text):
    if "urgent" in text.lower() or "click" in text.lower() or "bank" in text.lower():
        return "Danger: Contains urgent language or suspicious keywords."
    elif any(word in text.lower() for word in ["verify", "account", "password"]):
        return "Warning: Contains potential phishing indicators."
    else:
        return "Safe: No obvious phishing indicators."

def detect_text(text):
    urls = extract_urls(text)
    prompt = (
        "You are a phishing detector. Analyze the following text for phishing or social engineering risk. "
        "Return ONLY a compact JSON object with this exact shape and keys and NO extra prose, code fences, or formatting: "
        '{"risk":"SAFE|WARNING|DANGER","reasons":["concise reason 1","concise reason 2","concise reason 3"]}. '
        "Always include 3 to 7 concise, user-facing reasons tailored to the input. "
        "If SAFE, explain why it's safe (e.g., tone, sender, lack of malicious cues). "
        "If WARNING or DANGER, explain the strongest indicators. "
        "Text: "
    ) + text
    try:
        response = ollama_client.chat(model='mistral', messages=[{"role": "user", "content": prompt}])
        text_result = response['message']['content']
        return text_result
    except Exception as e:
        return f"LLM error: {str(e)}. Using mock analysis: {mock_phishing_analysis(text)}"

def extract_danger_level(analysis_result):
    def _strip_code_fences(text):
        text = text.strip()
        if text.startswith("```"):
            # Remove first fence line
            text = "\n".join(text.splitlines()[1:])
        if text.endswith("```"):
            # Remove trailing fence line
            lines = text.splitlines()
            if lines:
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return text

    # If it's already a dict-like object, try to read risk
    if isinstance(analysis_result, dict):
        risk = analysis_result.get("risk", "").strip().upper()
        if risk in ("SAFE", "WARNING", "DANGER"):
            return risk

    text_value = str(analysis_result)
    cleaned = _strip_code_fences(text_value)

    # Try JSON parse
    try:
        import json
        # Extract the first JSON object if extra text surrounds it
        start = cleaned.find('{')
        end = cleaned.rfind('}')
        if start != -1 and end != -1 and end > start:
            candidate = cleaned[start:end+1]
            obj = json.loads(candidate)
            risk = str(obj.get("risk", "")).strip().upper()
            if risk in ("SAFE", "WARNING", "DANGER"):
                return risk
    except Exception:
        pass

    import re
    # Prefer patterns that explicitly label risk
    label_regex = re.compile(r"\b(risk|risk level)\s*[:=-]?\s*\b(safe|warning|danger)\b", re.I)
    m = label_regex.search(cleaned)
    if m:
        return m.group(2).upper()

    # As a cautious fallback, look for standalone tokens; prefer more severe only if uniquely present
    has_danger = re.search(r"\b(danger)\b", cleaned, re.I) is not None
    has_warning = re.search(r"\b(warning)\b", cleaned, re.I) is not None
    has_safe = re.search(r"\b(safe)\b", cleaned, re.I) is not None and not re.search(r"\b(unsafe|not safe)\b", cleaned, re.I)

    if has_danger and not (has_warning or has_safe):
        return "DANGER"
    if has_warning and not has_danger:
        return "WARNING"
    if has_safe and not (has_danger or has_warning):
        return "SAFE"
    return "UNKNOWN"

def parse_analysis(analysis_result):
    def _strip_code_fences(text):
        text = text.strip()
        if text.startswith("```"):
            text = "\n".join(text.splitlines()[1:])
        if text.endswith("```"):
            lines = text.splitlines()
            if lines:
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        return text

    if isinstance(analysis_result, dict):
        risk = str(analysis_result.get("risk", "UNKNOWN")).upper()
        reasons = analysis_result.get("reasons", []) or []
        return {"risk": risk, "reasons": reasons if isinstance(reasons, list) else [str(reasons)]}

    text_value = str(analysis_result)
    cleaned = _strip_code_fences(text_value)
    try:
        import json
        start = cleaned.find('{')
        end = cleaned.rfind('}')
        if start != -1 and end != -1 and end > start:
            candidate = cleaned[start:end+1]
            obj = json.loads(candidate)
            risk = str(obj.get("risk", "UNKNOWN")).upper()
            reasons = obj.get("reasons", []) or []
            return {"risk": risk, "reasons": reasons if isinstance(reasons, list) else [str(reasons)]}
    except Exception:
        pass
    # Fallback to danger level extractor only
    return {"risk": extract_danger_level(analysis_result), "reasons": []}

def render_analysis(analysis_result):
    parsed = parse_analysis(analysis_result)
    risk = parsed.get("risk", "UNKNOWN").upper()
    reasons = parsed.get("reasons", [])
    st.markdown(f"**Risk Level: {risk}**")
    st.write("\n")
    st.markdown("**Reasons:**")
    if reasons:
        for idx, reason in enumerate(reasons, start=1):
            st.markdown(f"{idx}. {reason}")
    else:
        st.markdown("- No specific indicators provided by the analyzer.")

def get_danger_color(danger_level):
    if "DANGER" in danger_level:
        return "red"
    elif "WARNING" in danger_level:
        return "orange"
    elif "SAFE" in danger_level:
        return "green"
    else:
        return "gray"

def extract_urls(text):
    return re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

def url_features(url):
    parsed = extract(url)
    return {
        'length': len(url),
        'subdomains': len(parsed.subdomain.split('.')) if parsed.subdomain else 0,
        'https': url.startswith('https')
    }

def detect_url(url):
    prompt = (
        "You are a phishing detector. Analyze the following URL and its features for phishing risk. "
        "Return ONLY a compact JSON object with this exact shape and keys and NO extra prose, code fences, or formatting: "
        '{"risk":"SAFE|WARNING|DANGER","reasons":["concise reason 1","concise reason 2","concise reason 3"]}. '
        "Always include 3 to 7 concise, user-facing reasons tailored to the URL and features. "
        "If SAFE, explain why it's safe; if risky, highlight the strongest indicators. "
        "URL: "
        f"{url} "
        "Features: "
        f"{url_features(url)}"
    )
    try:
        response = ollama_client.chat(model='mistral', messages=[{"role": "user", "content": prompt}])
        return response['message']['content']
    except Exception as e:
        features = url_features(url)
        risk = "Safe" if features['https'] else "Warning"
        return f"LLM error: {str(e)}. Using mock analysis: {risk}: URL length {features['length']}, HTTPS: {features['https']}, subdomains: {features['subdomains']}."

def detect_qr(image_file):
    try:
        img = Image.open(image_file)
        decoded = decode(img)
        if decoded:
            content = decoded[0].data.decode('utf-8')
            if content.startswith('http'):
                return detect_url(content)
            else:
                return detect_text(content)
        return "No QR code found."
    except Exception as e:
        return f"Error decoding QR: {str(e)}"

def simple_voice_input(timeout=5, phrase_time_limit=8):
    recognizer = sr.Recognizer()
    
    st.write("Click the button below and speak your command:")
    
    if st.button("Start Listening", key="voice_listen"):
        with st.spinner("Listening... Speak now!"):
            try:
                with sr.Microphone() as source:
                    recognizer.adjust_for_ambient_noise(source, duration=0.5)
                    st.info("Speak now...")
                    audio = recognizer.listen(source, timeout=timeout, phrase_time_limit=phrase_time_limit)
                transcription = recognizer.recognize_google(audio)
                st.success(f"You said: {transcription}")
                return transcription
            except sr.UnknownValueError:
                st.error("Could not understand audio. Please try again.")
            except sr.RequestError as e:
                st.error(f"Speech recognition service error: {e}")
            except sr.WaitTimeoutError:
                st.error("Listening timeout. Please click the button again and speak.")
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    return None

def process_command_voice(email_user, email_pass):
    st.write("Voice Command Input")
    st.write("Speak commands like:")
    st.write("- 'check my email' or 'check my emails'")
    st.write("- 'check the recent email'")
    st.write("- 'check email with sender [sender name]'")
    st.write("- 'analyze this text'")
    
    transcription = simple_voice_input()
    
    if transcription:
        transcription_lower = transcription.lower()
        
        if "check my email" in transcription_lower:
            with st.spinner("Checking emails..."):
                result = check_emails(email_user, email_pass)
            st.write("Email Check Result")
            danger_counts = count_danger_levels(result)
            st.write(f"Security Summary: {danger_counts}")
            st.text_area("Detailed Results", result, height=300)
            
        elif "check the recent email" in transcription_lower:
            with st.spinner("Checking recent email..."):
                result = check_recent_email(email_user, email_pass)
            st.write("Recent Email Result")
            danger_level = extract_danger_level(result)
            st.write(f"Security Level: {danger_level}")
            st.text_area("Results", result, height=300)
            
        elif "check email with sender" in transcription_lower:
            sender = transcription_lower.replace("check email with sender", "").strip()
            if sender:
                with st.spinner(f"Searching for emails from '{sender}'..."):
                    result = check_emails_from_sender(email_user, email_pass, sender)
                st.write(f"Email Search Result from '{sender}'")
                danger_counts = count_danger_levels(result)
                st.write(f"Security Summary: {danger_counts}")
                st.text_area("Results", result, height=300)
            else:
                st.error("Please specify a sender name after 'check email with sender'")
                
        elif "check specific email" in transcription_lower:
            subject = transcription_lower.replace("check specific email", "").strip()
            if subject:
                with st.spinner(f"Searching for emails with subject '{subject}'..."):
                    result = check_specific_email(email_user, email_pass, subject)
                st.write(f"Email Search Result for '{subject}'")
                danger_counts = count_danger_levels(result)
                st.write(f"Security Summary: {danger_counts}")
                st.text_area("Results", result, height=300)
            else:
                st.error("Please specify an email subject after 'check specific email'")
                
        elif "analyze this text" in transcription_lower:
            text_to_analyze = transcription_lower.replace("analyze this text", "").strip()
            if text_to_analyze:
                with st.spinner("Analyzing text..."):
                    result = detect_text(text_to_analyze)
                st.write("Text Analysis Result")
                danger_level = extract_danger_level(result)
                st.write(f"Security Level: {danger_level}")
                render_analysis(result)
            else:
                st.error("Please speak some text to analyze after 'analyze this text'")
                
        else:
            st.warning("Command not recognized. Please try:")
            st.write("- 'check my email' or 'check my emails'")
            st.write("- 'check the recent email'")
            st.write("- 'check email with sender [sender name]'")
            st.write("- 'check specific email [subject]'")
            st.write("- 'analyze this text [your text here]'")

def count_danger_levels(results_text):
    danger_count = results_text.lower().count('danger')
    warning_count = results_text.lower().count('warning')
    safe_count = results_text.lower().count('safe')
    return f"Danger: {danger_count}, Warning: {warning_count}, Safe: {safe_count}"

def process_text_voice():
    st.write("Text Voice Input")
    st.write("Speak the text you want to analyze for phishing")
    transcription = simple_voice_input(timeout=10, phrase_time_limit=15)
    if transcription:
        st.write("Transcribed Text")
        st.text_area("Text to analyze", transcription, height=150)
        with st.spinner("Analyzing for phishing..."):
            result = detect_text(transcription)
        danger_level = extract_danger_level(result)
        st.write(f"Security Level: {danger_level}")
        st.write("Analysis Result")
        render_analysis(result)

def safe_decode(payload, charset=None):
    # Normalize various payload types defensively
    if isinstance(payload, str):
        return payload
    if isinstance(payload, bytes):
        try:
            if isinstance(charset, str) and charset:
                return payload.decode(charset, errors='replace')
            return payload.decode('utf-8', errors='replace')
        except Exception:
            return payload.decode('utf-8', errors='replace')
    # Fallback for unexpected types (e.g., int)
    try:
        return str(payload)
    except Exception:
        return ""

def check_emails(email_user, email_pass, limit=10):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, "ALL")
        email_ids = data[0].split()[-limit:]
        results = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            # Extract raw email bytes robustly
            raw_chunks = []
            for part in msg_data:
                if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                    raw_chunks.append(part[1])
                elif isinstance(part, (bytes, bytearray)):
                    raw_chunks.append(part)
            raw_email = b"".join(raw_chunks)
            if not raw_email:
                continue
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            from_address = msg["From"] or "Unknown Sender"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)
            analysis = detect_text(body)
            danger_level = extract_danger_level(analysis)
            results.append(f"{danger_level}\nFrom: {from_address}\nSubject: {subject}\nBody: {body[:200]}...\nAnalysis: {analysis}\n{'-'*50}")
        mail.logout()
        return "\n".join(results) if results else "No emails found."
    except Exception as e:
        return f"Error checking emails: {str(e)}"

def check_emails_structured(email_user, email_pass, limit=10):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, "ALL")
        email_ids = data[0].split()[-limit:]
        entries = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_chunks = []
            for part in msg_data:
                if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                    raw_chunks.append(part[1])
                elif isinstance(part, (bytes, bytearray)):
                    raw_chunks.append(part)
            raw_email = b"".join(raw_chunks)
            if not raw_email:
                continue
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            from_address = msg["From"] or "Unknown Sender"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)
            analysis = detect_text(body)
            parsed = parse_analysis(analysis)
            entries.append({
                "risk": parsed.get("risk", extract_danger_level(analysis)),
                "from": from_address,
                "subject": subject,
                "body_snippet": body[:400] + ("..." if len(body) > 400 else ""),
                "reasons": parsed.get("reasons", []),
            })
        mail.logout()
        return entries
    except Exception as e:
        return {"error": str(e)}

def check_recent_email(email_user, email_pass):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, "ALL")
        email_ids = data[0].split()
        if not email_ids:
            mail.logout()
            return "No emails found in inbox."
        email_id = email_ids[-1]
        status, msg_data = mail.fetch(email_id, "(RFC822)")
        raw_chunks = []
        for part in msg_data:
            if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                raw_chunks.append(part[1])
            elif isinstance(part, (bytes, bytearray)):
                raw_chunks.append(part)
        raw_email = b"".join(raw_chunks)
        if not raw_email:
            mail.logout()
            return "Failed to read recent email content."
        msg = email.message_from_bytes(raw_email, policy=email.policy.default)
        subject = msg["Subject"] or "No Subject"
        from_address = msg["From"] or "Unknown Sender"
        date = msg["Date"] or "Unknown Date"
        body = ""
        charset = msg.get_content_charset() or 'utf-8'
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = safe_decode(payload, charset)
                        break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)
        analysis = detect_text(body)
        danger_level = extract_danger_level(analysis)
        mail.logout()
        return f"{danger_level}\nFrom: {from_address}\nDate: {date}\nSubject: {subject}\nBody: {body[:500]}...\nAnalysis: {analysis}"
    except Exception as e:
        return f"Error checking recent email: {str(e)}"

def check_emails_from_sender(email_user, email_pass, sender_name):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, f'FROM "{sender_name}"')
        email_ids = data[0].split()
        results = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_chunks = []
            for part in msg_data:
                if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                    raw_chunks.append(part[1])
                elif isinstance(part, (bytes, bytearray)):
                    raw_chunks.append(part)
            raw_email = b"".join(raw_chunks)
            if not raw_email:
                continue
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            from_address = msg["From"] or "Unknown Sender"
            date = msg["Date"] or "Unknown Date"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)
            analysis = detect_text(body)
            danger_level = extract_danger_level(analysis)
            results.append(f"{danger_level}\nFrom: {from_address}\nDate: {date}\nSubject: {subject}\nBody: {body[:200]}...\nAnalysis: {analysis}\n{'-'*50}")
        mail.logout()
        return "\n".join(results) if results else f"No emails found from sender '{sender_name}'."
    except Exception as e:
        return f"Error checking emails from sender: {str(e)}"

def check_specific_email(email_user, email_pass, subject):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, f'SUBJECT "{subject}"')
        email_ids = data[0].split()
        results = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_chunks = []
            for part in msg_data:
                if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                    raw_chunks.append(part[1])
                elif isinstance(part, (bytes, bytearray)):
                    raw_chunks.append(part)
            raw_email = b"".join(raw_chunks)
            if not raw_email:
                continue
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            from_address = msg["From"] or "Unknown Sender"
            date = msg["Date"] or "Unknown Date"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)
            analysis = detect_text(body)
            danger_level = extract_danger_level(analysis)
            results.append(f"{danger_level}\nFrom: {from_address}\nDate: {date}\nSubject: {subject}\nBody: {body[:200]}...\nAnalysis: {analysis}\n{'-'*50}")
        mail.logout()
        return "\n".join(results) if results else f"No emails found with subject '{subject}'."
    except Exception as e:
        return f"Error checking specific email: {str(e)}"

def monitor_emails(email_user, email_pass, stop_event, queue_ref, check_interval_seconds: int = 120):
    processed_emails = set()
    try:
        persisted = processed_emails_collection.find_one({"email": email_user})
        if persisted:
            processed_emails = set(persisted.get("processed_ids", []))
    except Exception as e:
        print(f"Debug: Adding error to queue - Failed to load processed emails: {str(e)}")
        queue_ref.put(("error", f"Failed to load processed emails: {str(e)}"))
    last_check = datetime.now() - timedelta(minutes=10)
    mail = None
    try:
        while not stop_event.is_set():
            if not mail:
                try:
                    mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=30)
                    mail.login(email_user, email_pass)
                    mail.select("inbox")
                    print(f"Debug: Adding info to queue - Connected to {email_user} inbox at {datetime.now().strftime('%H:%M:%S')}")
                    queue_ref.put(("info", f"Connected to {email_user} inbox at {datetime.now().strftime('%H:%M:%S')}"))
                except Exception as e:
                    print(f"Debug: Adding error to queue - IMAP login failed: {str(e)}")
                    queue_ref.put(("error", f"IMAP login failed: {str(e)}. Retrying in 30 seconds..."))
                    if mail:
                        try:
                            mail.logout()
                        except:
                            pass
                    mail = None
                    time.sleep(30)
                    continue
            now = datetime.now()
            try:
                if (now - last_check).total_seconds() >= check_interval_seconds:
                    mail.noop()
                    fifteen_minutes_ago = (now - timedelta(minutes=15)).strftime('%d-%b-%Y')
                    status, data = mail.search(None, f'(SINCE "{fifteen_minutes_ago}")')
                    if status != 'OK':
                        print(f"Debug: Adding error to queue - Failed to search emails")
                        queue_ref.put(("error", "Failed to search emails"))
                        continue
                    email_ids = data[0].split()
                    new_emails = []
                    for email_id in email_ids:
                        # Normalize ID to a string key for set comparisons/persistence
                        id_key = email_id.decode() if isinstance(email_id, (bytes, bytearray)) else str(email_id)
                        if id_key not in processed_emails:
                            try:
                                # imaplib accepts str; ensure we pass string ID
                                fetch_id = id_key
                                status, msg_data = mail.fetch(fetch_id, "(RFC822)")
                                if status != 'OK':
                                    continue
                                raw_chunks = []
                                for part in msg_data:
                                    if isinstance(part, tuple) and isinstance(part[1], (bytes, bytearray)):
                                        raw_chunks.append(part[1])
                                    elif isinstance(part, (bytes, bytearray)):
                                        raw_chunks.append(part)
                                raw_email = b"".join(raw_chunks)
                                if not raw_email:
                                    continue
                                msg = email.message_from_bytes(raw_email, policy=email.policy.default)
                                subject = msg["Subject"] or "No Subject"
                                from_address = msg["From"] or "Unknown Sender"
                                date = msg["Date"] or "Unknown Date"
                                body = ""
                                charset = msg.get_content_charset() or 'utf-8'
                                if msg.is_multipart():
                                    for part in msg.walk():
                                        if part.get_content_type() == "text/plain":
                                            payload = part.get_payload(decode=True)
                                            if payload:
                                                body = safe_decode(payload, charset)
                                                break
                                else:
                                    payload = msg.get_payload(decode=True)
                                    if payload:
                                        body = safe_decode(payload, charset)
                                analysis = detect_text(body)
                                danger_level = extract_danger_level(analysis)
                                try:
                                    parsed = parse_analysis(analysis)
                                    reasons_list = parsed.get("reasons", [])
                                except Exception:
                                    reasons_list = []
                                reasons_items = "".join(f"<li>{r}</li>" for r in reasons_list) if reasons_list else "<li>No specific indicators provided.</li>"
                                new_emails.append({
                                    "from": from_address,
                                    "subject": subject,
                                    "date": date,
                                    "body_snippet": body[:200] + ("..." if len(body) > 200 else ""),
                                    "analysis": analysis,
                                    "danger_level": danger_level
                                })
                                processed_emails.add(id_key)
                            except Exception as e:
                                print(f"Debug: Adding error to queue - Error processing email {email_id}: {str(e)}")
                                queue_ref.put(("error", f"Error processing email {email_id}: {str(e)}"))
                                continue
                    try:
                        processed_emails_collection.update_one(
                            {"email": email_user},
                            {"$set": {"processed_ids": list(processed_emails), "last_updated": now}},
                            upsert=True
                        )
                    except Exception as e:
                        print(f"Debug: Adding warning to queue - Failed to save processed emails: {str(e)}")
                        queue_ref.put(("warning", f"Failed to save processed emails: {str(e)}"))
                    try:
                        email_checks_collection.insert_one({
                            "email": email_user,
                            "timestamp": now,
                            "emails_checked": len(email_ids),
                            "new_emails_found": len(new_emails)
                        })
                    except Exception as e:
                        print(f"Debug: Adding warning to queue - Failed to log email check: {str(e)}")
                        queue_ref.put(("warning", f"Failed to log email check: {str(e)}"))
                    if new_emails:
                        print(f"Debug: Adding success to queue - NEW EMAILS DETECTED at {now.strftime('%H:%M:%S')} ({len(new_emails)})")
                        queue_ref.put(("success", f"NEW EMAILS DETECTED ({len(new_emails)}) at {now.strftime('%H:%M:%S')}"))
                        has_danger = any(e['danger_level'] == 'DANGER' for e in new_emails)
                        for i, email_data in enumerate(new_emails, 1):
                            color = get_danger_color(email_data['danger_level'])
                            # Parse reasons again here for display (safe if missing)
                            try:
                                parsed_disp = parse_analysis(email_data['analysis'])
                                reasons_disp = parsed_disp.get('reasons', [])
                            except Exception:
                                reasons_disp = []
                            reasons_items = "".join(f"<li style=\"color:#000;\">{html.escape(str(r))}</li>" for r in reasons_disp) if reasons_disp else "<li style=\"color:#000;\">No specific indicators provided.</li>"
                            subj = html.escape(email_data['subject'])
                            frm = html.escape(email_data['from'])
                            dt = html.escape(email_data['date'])
                            preview = html.escape(email_data['body_snippet'])
                            email_display = f"""
                            <div style=\"border: 2px solid {color}; padding: 15px; margin: 10px 0; border-radius: 10px; background-color: #fff; color:#000;\">
                                <h3 style=\"color: {color}; margin-bottom: 10px;\">{email_data['danger_level']}</h3>
                                <div style=\"font-weight: bold; font-size: 16px; color:#000;\">Subject: {subj}</div>
                                <div style=\"color:#000;\">From: {frm}</div>
                                <div style=\"color:#000;\">Date: {dt}</div>
                                <div style=\"color:#000;\">Preview: {preview}</div>
                                <div style=\"margin-top: 10px; font-weight: 600; color:#000;\">Reasons:</div>
                                <ol style=\"margin-top: 4px; color:#000;\">{reasons_items}</ol>
                            </div>
                            """
                            print(f"Debug: Adding email to queue - Email {i} from {email_data['from']}")
                            queue_ref.put(("email", email_display))
                        if has_danger:
                            queue_ref.put(("alert", "DANGER_DETECTED"))
                    else:
                        print(f"Debug: Adding info to queue - No new emails found at {now.strftime('%H:%M:%S')}")
                        queue_ref.put(("info", f"No new emails found at {now.strftime('%H:%M:%S')}. Checked {len(email_ids)} emails."))
                    last_check = now
            except Exception as e:
                print(f"Debug: Adding error to queue - Error during email check: {str(e)}")
                queue_ref.put(("error", f"Error during email check: {str(e)}. Reconnecting..."))
                if mail:
                    try:
                        mail.logout()
                    except:
                        pass
                mail = None
                continue
            time.sleep(5)
    except Exception as e:
        print(f"Debug: Adding error to queue - Error monitoring emails: {str(e)}")
        queue_ref.put(("error", f"Error monitoring emails: {str(e)}"))
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass

st.title("Phishing & Social Engineering Detector")
st.write("Voice-enabled phishing detection using local LLM")

col1, col2 = st.columns(2)
with col1:
    email_user = st.text_input("Enter Email", value=default_email)
with col2:
    email_pass = st.text_input("Enter Password", type="password", value=default_pass)

col1, col2 = st.columns(2)
with col1:
    if st.button("Save Credentials"):
        if email_user and email_pass:
            hashed_password = bcrypt.hashpw(email_pass.encode('utf-8'), bcrypt.gensalt())
            credentials = {"email": email_user, "password": hashed_password, "timestamp": datetime.now()}
            try:
                credentials_collection.update_one({"email": email_user}, {"$set": credentials}, upsert=True)
                st.success(f"Credentials for {email_user} saved/updated!")
            except Exception as e:
                st.error(f"Database error: {str(e)}")
        else:
            st.error("Email and password required.")
with col2:
    if st.button("Delete Credentials"):
        if email_user:
            try:
                result = credentials_collection.delete_one({"email": email_user})
                if result.deleted_count > 0:
                    st.success(f"Credentials for {email_user} deleted!")
                else:
                    st.warning(f"No credentials found for {email_user}.")
            except Exception as e:
                st.error(f"Database error: {str(e)}")
        else:
            st.error("Enter an email address to delete.")

if st.button("View Stored Credentials"):
    try:
        credentials = list(credentials_collection.find({}, {"password": 0}))
        if credentials:
            for cred in credentials:
                st.write(f"Email: {cred['email']}, Timestamp: {cred['timestamp']}")
        else:
            st.warning("No credentials found.")
    except Exception as e:
        st.error(f"Database error: {str(e)}")

if st.button("Debug Session State"):
    st.write("Session State Contents:")
    st.write(st.session_state)

st.header("Choose Detection Method")
input_type = st.selectbox("Select input type:", 
                         ["Text/Email", "URL", "QR Image", "Voice Command", "Text Voice Input", "Check Emails", "Monitor Emails"])

if input_type == "Text/Email":
    text = st.text_area("Enter text or email content", height=150)
    if st.button("Analyze Text"):
        with st.spinner("Analyzing..."):
            result = detect_text(text)
        danger_level = extract_danger_level(result)
        st.write(f"Security Level: {danger_level}")
        st.write("Analysis Result")
        render_analysis(result)

elif input_type == "URL":
    url = st.text_input("Enter URL to analyze")
    if st.button("Analyze URL"):
        with st.spinner("Analyzing URL..."):
            result = detect_url(url)
        danger_level = extract_danger_level(result)
        st.write(f"Security Level: {danger_level}")
        st.write("URL Analysis Result")
        render_analysis(result)

elif input_type == "QR Image":
    uploaded = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg"])
    if uploaded and st.button("Analyze QR Code"):
        with st.spinner("Decoding and analyzing QR code..."):
            result = detect_qr(uploaded)
        danger_level = extract_danger_level(result)
        st.write(f"Security Level: {danger_level}")
        st.write("QR Code Analysis Result")
        render_analysis(result)

elif input_type == "Voice Command":
    if email_user and email_pass:
        process_command_voice(email_user, email_pass)
    else:
        st.error("Please enter email and password first for email commands.")

elif input_type == "Text Voice Input":
    process_text_voice()

elif input_type == "Check Emails":
    if email_user and email_pass:
        with st.spinner("Checking emails..."):
            entries = check_emails_structured(email_user, email_pass)
        if isinstance(entries, dict) and entries.get("error"):
            st.error(f"Error: {entries['error']}")
        elif not entries:
            st.info("No emails found.")
        else:
            # Summary
            summary_text = "\n".join(f"{e['risk']}" for e in entries)
            st.write(f"Security Summary: {count_danger_levels(summary_text)}")
            # Render each email cleanly
            for e in entries:
                color = get_danger_color(e['risk'])
                st.markdown(f"**{e['risk']}**", unsafe_allow_html=False)
                st.write(f"From: {e['from']}")
                st.write(f"Subject: {e['subject']}")
                if e.get('body_snippet'):
                    st.write("Body:")
                    st.code(e['body_snippet'])
                st.markdown("**Reasons:**")
                if e.get('reasons'):
                    for i, r in enumerate(e['reasons'], start=1):
                        st.markdown(f"{i}. {r}")
                else:
                    st.markdown("- No specific indicators provided.")
                st.markdown("---")
    else:
        st.error("Please enter email and password first.")

elif input_type == "Monitor Emails":
    if email_user and email_pass:
        status_placeholder = st.empty()
        messages_placeholder = st.empty()

        if not st.session_state.monitoring_active:
            if st.button("Start Monitoring"):
                try:
                    cred = credentials_collection.find_one({"email": email_user})
                    if cred and bcrypt.checkpw(email_pass.encode('utf-8'), cred["password"]):
                        st.session_state.monitoring_active = True
                        st.session_state.monitoring_messages = []
                        st.session_state.last_check_time = None
                        st.session_state.stop_event = threading.Event()
                        st.session_state.check_interval_seconds = 120
                        st.session_state.monitor_thread = threading.Thread(
                            target=monitor_emails, 
                            args=(email_user, email_pass, st.session_state.stop_event, st.session_state.message_queue, st.session_state.check_interval_seconds), 
                            daemon=True
                        )
                        st.session_state.monitor_thread.start()
                        status_placeholder.success("Monitoring started! Checking for new emails every 2 minutes.")
                    else:
                        st.error("Invalid email or password.")
                except Exception as e:
                    st.error(f"Database error: {str(e)}")

        if st.session_state.monitoring_active:
            current_time = datetime.now().strftime('%H:%M:%S')
            last_check_display = st.session_state.last_check_time or "Waiting for first check..."
            interval = st.session_state.get('check_interval_seconds', 120)
            status_placeholder.info(f"Monitoring active for {email_user} - Last check: {last_check_display} - Next check every {interval}s - Current time: {current_time}")

            # Thread health check and auto-restart option
            if not (st.session_state.monitor_thread and st.session_state.monitor_thread.is_alive()):
                if st.button("Restart Monitoring"):
                    try:
                        st.session_state.stop_event = threading.Event()
                        st.session_state.monitor_thread = threading.Thread(
                            target=monitor_emails,
                            args=(email_user, email_pass, st.session_state.stop_event, st.session_state.message_queue, interval),
                            daemon=True
                        )
                        st.session_state.monitor_thread.start()
                        status_placeholder.success("Monitoring thread restarted.")
                    except Exception as e:
                        st.error(f"Failed to restart monitoring: {e}")
            
            new_messages = []
            while True:
                try:
                    msg_type, msg = st.session_state.message_queue.get_nowait()
                    print(f"Debug: UI processing message - Type: {msg_type}, Content: {msg}")
                    if msg_type == "info" and "No new emails found at" in msg:
                        check_time = msg.split("at ")[-1].split('.')[0]
                        st.session_state.last_check_time = check_time
                    elif msg_type == "success" and "NEW EMAILS DETECTED" in msg:
                        # Supports messages like: NEW EMAILS DETECTED (N) at HH:MM:SS
                        check_time = msg.split("at ")[-1].strip()
                        st.session_state.last_check_time = check_time
                    new_messages.append((msg_type, msg))
                except Empty:
                    break
                except Exception as e:
                    new_messages.append(("error", f"Error retrieving message: {str(e)}"))
                    break

            for msg_type, msg in new_messages:
                if (msg_type, msg) not in st.session_state.monitoring_messages:
                    st.session_state.monitoring_messages.append((msg_type, msg))

            max_messages = 50
            st.session_state.monitoring_messages = st.session_state.monitoring_messages[-max_messages:]

            with messages_placeholder.container():
                if st.session_state.monitoring_messages:
                    danger_counts = count_danger_levels("\n".join(msg for _, msg in st.session_state.monitoring_messages))
                    st.write(f"Security Summary: {danger_counts}")
                    for msg_type, msg in st.session_state.monitoring_messages:
                        if msg_type == "error":
                            st.error(msg)
                        elif msg_type == "warning":
                            st.warning(msg)
                        elif msg_type == "info":
                            st.info(msg)
                        elif msg_type == "success":
                            st.success(msg)
                        elif msg_type == "email":
                            try:
                                st.markdown(msg, unsafe_allow_html=True)
                            except Exception as e:
                                st.write(f"Email display error: {e} - Content: {msg}")
                        elif msg_type == "alert":
                            # Stop monitoring and play a beep to alert user
                            if st.session_state.monitoring_active:
                                st.session_state.monitoring_active = False
                                if hasattr(st.session_state, 'stop_event'):
                                    try:
                                        st.session_state.stop_event.set()
                                    except Exception:
                                        pass
                            st.error("Danger email detected. Monitoring stopped. Messages remain visible for review.")
                            # Generate a short beep sound
                            try:
                                def _generate_beep_bytes(duration_ms=500, freq=880, sample_rate=44100):
                                    num_samples = int(sample_rate * (duration_ms / 1000.0))
                                    buffer = _io.BytesIO()
                                    with _wave.open(buffer, 'wb') as wf:
                                        wf.setnchannels(1)
                                        wf.setsampwidth(2)
                                        wf.setframerate(sample_rate)
                                        for i in range(num_samples):
                                            t = i / sample_rate
                                            sample = int(32767 * 0.4 * _math.sin(2 * _math.pi * freq * t))
                                            wf.writeframes(_struct.pack('<h', sample))
                                    return buffer.getvalue()
                                st.audio(_generate_beep_bytes(), format='audio/wav')
                            except Exception:
                                pass
                        else:
                            st.write(msg)
                else:
                    st.info("Monitoring active. Waiting for new emails...")

            # If we received new messages, refresh immediately with debounce to avoid rerun loops
            if new_messages and st.session_state.monitoring_active:
                now_ts = datetime.now()
                last = st.session_state.get('last_ui_update')
                if not last or (now_ts - last).total_seconds() > 1.5:
                    st.session_state.last_ui_update = now_ts
                    try:
                        st.rerun()
                    except Exception:
                        pass

            if st.button("Stop Monitoring"):
                st.session_state.monitoring_active = False
                if hasattr(st.session_state, 'stop_event'):
                    st.session_state.stop_event.set()
                status_placeholder.success("Monitoring stopped. Messages remain visible for review.")
                # Do NOT clear messages or force a rerun; keep UI as-is so the user can review

            if st.session_state.monitoring_active:
                if (datetime.now() - st.session_state.last_ui_update).total_seconds() > 10:
                    st.session_state.last_ui_update = datetime.now()
                    st.rerun()
                
    else:
        st.error("Please enter email and password first.")

with st.expander("Installation Requirements"):
    st.write("""
    **Required packages:**
    ```
    pip install streamlit speechrecognition pyaudio tldextract pyzbar pillow pymongo bcrypt ollama python-dotenv requests
    ```
    
    **For voice recognition on Windows:**
    ```
    pip install pyaudio
    ```
    
    **For voice recognition on macOS:**
    ```
    brew install portaudio
    pip install pyaudio
    ```
    
    **For voice recognition on Linux:**
    ```
    sudo apt-get install python3-pyaudio
    ```
    """)

with st.expander("Troubleshooting Voice Input"):
    st.write("""
    **If voice input doesn't work:**
    1. Make sure your microphone is connected and working
    2. Check browser permissions for microphone access
    3. Try using Chrome or Firefox instead of Safari
    4. Ensure you have the required audio drivers installed
    
    **Common issues:**
    - Microphone not detected: Check device manager/sound settings
    - Permission denied: Allow microphone access in browser
    - Audio quality: Speak clearly and reduce background noise
    """)