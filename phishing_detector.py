import streamlit as st
from langchain_core.prompts import PromptTemplate
from langchain_openai import OpenAI
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image

# Set up OpenAI LLM with API key from Streamlit secrets (set during deployment)
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

# QR Code Detection (in-memory processing)
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
st.title("Phishing & Social Engineering Detector (Cloud LLM Version)")

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