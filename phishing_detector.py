import streamlit as st
from langchain_core.prompts import PromptTemplate
from langchain_openai import OpenAI
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import imaplib
import email
from streamlit_webrtc import webrtc_streamer, AudioProcessorBase, RTCConfiguration, WebRtcMode

# Set up OpenAI LLM with API key from Streamlit secrets
try:
    llm = OpenAI(api_key=st.secrets.get("OPENAI_API_KEY"), model="gpt-3.5-turbo")
except KeyError:
    st.error("OpenAI API key not found. Please set it in Streamlit secrets during deployment.")
    st.stop()

# Define prompt template
prompt = PromptTemplate(
    input_variables=["text"],
    template="Analyze this: {text}. Is it phishing or social engineering? Give risk level (low/medium/high) and reasons."
)

# Text Detection (Emails/Messages)
def detect_text(text):
    urls = extract_urls(text)
    analysis = prompt | llm
    text_result = analysis.invoke({"text": text})
    if urls:
        url_result = detect_url(urls[0])
        return text_result + "\nURL Analysis: " + url_result
    return text_result

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
    features = url_features(url)
    prompt_url = f"Analyze URL: {url}. Features: {features}. Risk level (low/medium/high) and reasons:"
    return llm.invoke(prompt_url)

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

# Voice Detection (simulated with text)
def detect_voice(text_input):
    if not text_input:
        return "Please enter text to simulate voice input."
    return detect_text(text_input)

# Email Checking Function
def check_emails():
    try:
        # Connect to email server (e.g., Gmail IMAP settings)
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

# Audio Processor for Real Voice Input
class AudioProcessor(AudioProcessorBase):
    def recv(self, frame):
        return frame  # Return the audio frame for processing

# Real Voice Input Function
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
                # Use OpenAI Whisper for transcription (requires OpenAI API)
                transcription = llm.invoke("Transcribe this audio: " + audio_frame)  # Simplified; use Whisper API for accurate STT
                st.write(f"Transcribed: {transcription}")
                # Parse command
                if "check my emails" in transcription.lower():
                    st.write(check_emails())
                elif "check specific email" in transcription.lower():
                    st.write("Specify the email ID or subject.")  # Extend for specific email fetching
                else:
                    st.write(detect_text(transcription))
    except Exception as e:
        return f"Error processing voice: {str(e)}"

# Streamlit UI
st.title("Phishing & Social Engineering Detector (Cloud LLM Version)")

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
        st.write(detect_voice(text_input))

elif input_type == "Check Emails":
    if st.button("Check Latest Emails"):
        st.write(check_emails())

elif input_type == "Real Voice Command":
    process_voice()