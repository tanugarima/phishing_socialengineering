import streamlit as st
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import requests

# VirusTotal API setup (replace with your free API key)
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"

# Mock heuristic fallback
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
    if VIRUSTOTAL_API_KEY:
        try:
            result = analyze_with_virustotal(text if not urls else urls[0])
            if result:
                return result
        except Exception as e:
            st.warning(f"VirusTotal API error: {str(e)}. Using mock analysis.")
            return mock_phishing_analysis(text)
    else:
        st.warning("VirusTotal API key not set. Using mock analysis.")
        return mock_phishing_analysis(text)
    if urls:
        url_result = detect_url(urls[0])
        return result + "\nURL Analysis: " + url_result
    return result

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

# Analyze with VirusTotal (simplified for text via URL context)
def analyze_with_virustotal(input_data):
    if isinstance(input_data, str) and not input_data.startswith('http'):
        # For text, create a dummy URL or use text as context (limited by API)
        return mock_phishing_analysis(input_data)  # VirusTotal doesn't directly analyze text; use mock
    elif isinstance(input_data, str):
        response = requests.post(
            VIRUSTOTAL_URL,
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            json={"url": input_data}
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
    return "Invalid input for analysis."

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

# Streamlit UI
st.title("Phishing & Social Engineering Detector (Free API Version)")

input_type = st.selectbox("Choose Input", ["Text (Email/Message)", "URL", "QR Code Image", "Voice (Text Simulation)"])

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