import streamlit as st
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import imaplib
import email
from vosk import Model, KaldiRecognizer, SetLogLevel
import os
import json
from queue import Queue
from streamlit_webrtc import webrtc_streamer, AudioProcessorBase, RTCConfiguration, WebRtcMode
from ollama import Client
from dotenv import load_dotenv
import email.policy

# Load environment variables
load_dotenv()
email_user = os.getenv("EMAIL_USER", "")
email_pass = os.getenv("EMAIL_PASS", "")

# Ollama client setup (runs locally)
ollama_client = Client(host='http://localhost:11434')  # Default Ollama port

# Mock heuristic for fallback
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
    prompt = f"Analyze this text for phishing or social engineering: {text}. Provide risk level (low/medium/high) and reasons."
    try:
        response = ollama_client.chat(model='mistral', messages=[{"role": "user", "content": prompt}])
        text_result = response['message']['content']
        if urls:
            url_result = detect_url(urls[0])
            return text_result + "\nURL Analysis: " + url_result
        return text_result
    except Exception as e:
        st.warning(f"LLM error: {str(e)}. Using mock analysis.")
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
    prompt = f"Analyze this URL for phishing: {url}. Features: {url_features(url)}. Provide risk level (low/medium/high) and reasons."
    try:
        response = ollama_client.chat(model='mistral', messages=[{"role": "user", "content": prompt}])
        return response['message']['content']
    except Exception as e:
        st.warning(f"LLM error: {str(e)}. Using mock analysis.")
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
            st.write(f"Decoded QR Content: {content}")  # Debug output
            if content.startswith('http'):
                return detect_url(content)
            else:
                return detect_text(content)
        return "No QR code found."
    except Exception as e:
        return f"Error decoding QR: {str(e)}"

# Voice Detection Classes
class CommandVoiceProcessor(AudioProcessorBase):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        possible_models = ["vosk-model-small-en-us-0.15", "vosk-model-en-us-0.22"]
        self.model = None
        for model_name in possible_models:
            model_path = os.path.join(base_dir, model_name)
            if os.path.exists(model_path) and os.path.isdir(model_path):
                self.model = Model(model_path)
                break
        if not self.model:
            raise ValueError(f"No valid Vosk model found in {base_dir}. Check folder names: {possible_models}")
        self.recognizer = KaldiRecognizer(self.model, 16000)  # Sample rate 16000 Hz
        SetLogLevel(0)  # Enable minimal logging for debugging
        self.transcription_queue = Queue()
        self.current_transcription = ""

    def recv(self, frame):
        if frame is not None:
            data = frame.to_ndarray().tobytes()
            if self.recognizer.AcceptWaveform(data):
                result = json.loads(self.recognizer.Result())
                self.current_transcription = result.get("text", "")
                st.write(f"Vosk Result: {self.current_transcription}")  # Debug output
                self.transcription_queue.put(self.current_transcription)
            else:
                partial = json.loads(self.recognizer.PartialResult())
                self.current_transcription = partial.get("partial", "")
                st.write(f"Vosk Partial: {self.current_transcription}")  # Debug output
                self.transcription_queue.put(self.current_transcription)
        return self.current_transcription

def process_command_voice():
    try:
        ctx = webrtc_streamer(
            key="command-voice-input",
            mode=WebRtcMode.SENDONLY,
            rtc_configuration=RTCConfiguration({"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]}),
            media_stream_constraints={"audio": {"sampleRate": 16000, "channelCount": 1}, "video": False},
            audio_processor_factory=CommandVoiceProcessor,
        )
        if ctx.state.playing:
            st.write("Listening for commands... (e.g., 'check my emails' or 'check specific email [subject]')")
            audio_processor = ctx.audio_processor
            while ctx.state.playing:
                if audio_processor.transcription_queue.qsize() > 0:
                    transcription = audio_processor.transcription_queue.get()
                    st.write(f"Command Recognized: {transcription}")
                    if "check my emails" in transcription.lower():
                        st.write(check_emails())
                    elif "check specific email" in transcription.lower():
                        subject = transcription.lower().replace("check specific email", "").strip()
                        if subject:
                            st.write(check_specific_email(subject))
                        else:
                            st.write("Please specify an email subject or ID after 'check specific email'.")
                    ctx.state.playing = False  # Stop after command
    except Exception as e:
        st.error(f"Error in command voice processing: {str(e)}")

class TextVoiceProcessor(AudioProcessorBase):
    def __init__(self):
        base_dir = os.path.dirname(__file__)
        possible_models = ["vosk-model-small-en-us-0.15", "vosk-model-en-us-0.22"]
        self.model = None
        for model_name in possible_models:
            model_path = os.path.join(base_dir, model_name)
            if os.path.exists(model_path) and os.path.isdir(model_path):
                self.model = Model(model_path)
                break
        if not self.model:
            raise ValueError(f"No valid Vosk model found in {base_dir}. Check folder names: {possible_models}")
        self.recognizer = KaldiRecognizer(self.model, 16000)  # Sample rate 16000 Hz
        SetLogLevel(0)  # Enable minimal logging for debugging
        self.transcription_queue = Queue()
        self.current_transcription = ""

    def recv(self, frame):
        if frame is not None:
            data = frame.to_ndarray().tobytes()
            if self.recognizer.AcceptWaveform(data):
                result = json.loads(self.recognizer.Result())
                self.current_transcription += result.get("text", "") + " "
                st.write(f"Vosk Result: {self.current_transcription}")  # Debug output
                self.transcription_queue.put(self.current_transcription)
            else:
                partial = json.loads(self.recognizer.PartialResult())
                self.current_transcription += partial.get("partial", "") + " "
                st.write(f"Vosk Partial: {self.current_transcription}")  # Debug output
                self.transcription_queue.put(self.current_transcription)
        return self.current_transcription.strip()

def process_text_voice():
    try:
        ctx = webrtc_streamer(
            key="text-voice-input",
            mode=WebRtcMode.SENDONLY,
            rtc_configuration=RTCConfiguration({"iceServers": [{"urls": ["stun:stun.l.google.com:19302"]}]}),
            media_stream_constraints={"audio": {"sampleRate": 16000, "channelCount": 1}, "video": False},
            audio_processor_factory=TextVoiceProcessor,
        )
        if ctx.state.playing:
            st.write("Reading mode: Speak the text to analyze (e.g., read an email). Press stop when done.")
            audio_processor = ctx.audio_processor
            transcription = ""
            while ctx.state.playing:
                if audio_processor.transcription_queue.qsize() > 0:
                    current_text = audio_processor.transcription_queue.get()
                    if current_text != transcription:
                        transcription = current_text
                        st.write(f"Transcribed so far: {transcription}")
            if transcription:
                st.write(f"Final Transcribed Text: {transcription}")
                st.write(detect_text(transcription))
    except Exception as e:
        st.error(f"Error in text voice processing: {str(e)}")

# Email Checking Functions
def safe_decode(payload, charset=None):
    try:
        if charset:
            return payload.decode(charset)
        return payload.decode('utf-8', errors='replace')  # Replace invalid chars with �
    except (UnicodeDecodeError, LookupError):
        return payload.decode('utf-8', errors='replace')  # Fallback with replacement

def check_emails():
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        if not email_user or not email_pass:
            return "Email or password not set in .env file. Please configure EMAIL_USER and EMAIL_PASS."
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, "ALL")
        email_ids = data[0].split()

        results = []
        for email_id in email_ids[-5:]:  # Check last 5 emails
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'

            if msg.is_multipart():
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)

            results.append(f"Subject: {subject}\nBody: {body[:200]}...\nAnalysis: {detect_text(body)}")

        mail.logout()
        return "\n\n".join(results) if results else "No emails found or error occurred."
    except Exception as e:
        return f"Error checking emails: {str(e)}"

def check_specific_email(subject):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        if not email_user or not email_pass:
            return "Email or password not set in .env file. Please configure EMAIL_USER and EMAIL_PASS."
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, data = mail.search(None, f'SUBJECT "{subject}"')
        email_ids = data[0].split()

        results = []
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            subject = msg["Subject"] or "No Subject"
            body = ""
            charset = msg.get_content_charset() or 'utf-8'

            if msg.is_multipart():
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = safe_decode(payload, charset)
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = safe_decode(payload, charset)

            results.append(f"Subject: {subject}\nBody: {body[:200]}...\nAnalysis: {detect_text(body)}")

        mail.logout()
        return "\n\n".join(results) if results else f"No emails found with subject '{subject}'."
    except Exception as e:
        return f"Error checking specific email: {str(e)}"

# Streamlit UI
st.title("Phishing & Social Engineering Detector (Local LLM Version)")

input_type = st.selectbox("Choose Input", ["Text/Email", "URL", "QR Image", "Command Voice Input", "Text Voice Input", "Check Emails"])

if input_type == "Text/Email":
    text = st.text_area("Enter text or email (e.g., 'Click here to reset password')")
    if st.button("Detect"):
        st.write(detect_text(text))

elif input_type == "URL":
    url = st.text_input("Enter URL (e.g., http://fake.com)")
    if st.button("Detect"):
        st.write(detect_url(url))

elif input_type == "QR Image":
    uploaded = st.file_uploader("Upload QR image (PNG/JPG)", type=["png", "jpg"])
    if uploaded and st.button("Detect"):
        st.write(detect_qr(uploaded))

elif input_type == "Command Voice Input":
    process_command_voice()

elif input_type == "Text Voice Input":
    process_text_voice()

elif input_type == "Check Emails":
    if st.button("Check Last 5 Emails"):
        st.write(check_emails())