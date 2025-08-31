import streamlit as st
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import imaplib
import email
from streamlit_webrtc import webrtc_streamer, AudioProcessorBase, RTCConfiguration, WebRtcMode
import requests

# VirusTotal API setup
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# Mock heuristic for text analysis
def mock_phishing_analysis(text):
    if "urgent" in text.lower() or "click" in text.lower() or "bank" in text.lower():
        return "High risk: Contains urgent language or suspicious keywords."
    elif any(word in text.lower() for word in ["verify", "account", "password"]):
        return "Medium risk: Contains potential phishing indicators."
    else:
        return "Low risk: No obvious phishing indicators."

# Text Detection (Emails/Messages)
def detect_text(text):
    urls = extract_urls(text)
    if VIRUSTOTAL_API_KEY and urls:
        try:
            result = detect_url(urls[0])
            return result + "\nText Analysis: " + mock_phishing_analysis(text)
        except Exception as e:
            st.warning(f"VirusTotal API error: {str(e)}. Using mock analysis.")
            return mock_phishing_analysis(text)
    else:
        st.warning("VirusTotal API key not set or no URL found. Using mock analysis.")
        return mock_phishing_analysis(text)

# URL Detection
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
    if VIRUSTOTAL_API_KEY:
        try:
            response = requests.post(
                VIRUSTOTAL_URL,
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                json={"url": url}
            )
            response.raise_for_status()
            data = response.json()
            verdict = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            if verdict.get('malicious', 0) > 0:
                return f"High risk: Detected as malicious by {verdict.get('malicious')} engines."
            elif verdict.get('suspicious', 0) > 0:
                return f"Medium risk: Detected as suspicious by {verdict.get('suspicious')} engines."
            else:
                return "Low risk: No malicious or suspicious detection."
        except Exception as e:
            st.warning(f"VirusTotal API error: {str(e)}. Using mock analysis.")
            features = url_features(url)
            risk = "Low risk" if features['https'] else "Medium risk"
            return f"{risk}: URL length {features['length']}, HTTPS: {features['https']}, subdomains: {features['subdomains']}."
    else:
        st.warning("VirusTotal API key not set. Using mock analysis.")
        features = url_features(url)
        risk = "Low risk" if features['https'] else "Medium risk"
        return f"{risk}: URL length {features['length']}, HTTPS: {features['https']}, subdomains: {features['subdomains']}."

# QR Code Detection
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

# Voice Detection (real-time with fallback)
class AudioProcessor(AudioProcessorBase):
    def recv(self, frame):
        return frame

def process_voice():
    try:
        ctx = webrtc_streamer(
            key="voice-input",
            mode=WebRtcMode.SENDRECV,
            rtc_configuration=RTCConfiguration({"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]}),
            audio_processor_factory=AudioProcessor,
        )
        if ctx.state.playing:
            st.write("Listening...")
            audio_frame = ctx.audio_receiver.get_frame()
            if audio_frame:
                # Simplified transcription (mock for now; replace with STT API if needed)
                transcription = "sample voice input"  # Placeholder; use a free STT API like AssemblyAI
                st.write(f"Transcribed: {transcription}")
                if "check my emails" in transcription.lower():
                    st.write(check_emails())
                else:
                    st.write(detect_text(transcription))
    except Exception as e:
        return f"Error processing voice: {str(e)}"

# Email Checking Function
def check_emails():
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        email_user = st.secrets.get("EMAIL_USER", "")
        email_pass = st.secrets.get("EMAIL_PASS", "")
        if not email_user or not email_pass:
            return "Email or password not set in secrets. Please configure EMAIL_USER and EMAIL_PASS."

        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, "ALL")
        email_ids = data[0].split()

        results = []
        for email_id in email_ids[-5:]:  # Check last 5 emails
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            subject = msg["Subject"]
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        results.append(f"Subject: {subject}\nBody: {body[:200]}...\nAnalysis: {detect_text(body)}")
            else:
                body = msg.get_payload(decode=True).decode()
                results.append(f"Subject: {subject}\nBody: {body[:200]}...\nAnalysis: {detect_text(body)}")

        mail.logout()
        return "\n\n".join(results) if results else "No emails found or error occurred."
    except Exception as e:
        return f"Error checking emails: {str(e)}"

# Streamlit UI
st.title("Phishing & Social Engineering Detector (Free API Version)")

input_type = st.selectbox("Choose Input", ["Text (Email/Message)", "URL", "QR Code Image", "Voice (Text Simulation)", "Check Emails", "Real Voice Command"])

if input_type == "Text (Email/Message)":
    text = st.text_area("Enter email or message (e.g., 'Click here to reset password')")
    if st.button("Detect"):
        st.write(detect_text(text))

elif input_type == "URL":
    url = st.text_input("Enter URL (e.g., http://fake.com)")
    if st.button("Detect"):
        st.write(detect_url(url))

elif input_type == "QR Code Image":
    uploaded = st.file_uploader("Upload QR image (PNG/JPG)", type=["png", "jpg"])
    if uploaded and st.button("Detect"):
        st.write(detect_qr(uploaded))

elif input_type == "Voice (Text Simulation)":
    text_input = st.text_area("Enter text to simulate voice input (e.g., 'Urgent bank alert')")
    if st.button("Detect"):
        st.write(detect_text(text_input))

elif input_type == "Check Emails":
    if st.button("Check Latest Emails"):
        st.write(check_emails())

elif input_type == "Real Voice Command":
    process_voice()