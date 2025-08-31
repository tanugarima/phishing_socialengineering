import streamlit as st
from langchain_core.prompts import PromptTemplate
from langchain_ollama import OllamaLLM
import re
from tldextract import extract
from pyzbar.pyzbar import decode
from PIL import Image
import speech_recognition as sr
import json

# Set up the local LLM
llm = OllamaLLM(model="mistral")  # Change to "mistral" if Llama 3 is slow

# Define how the LLM analyzes inputs
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
def decode_qr(image_path):
    img = Image.open(image_path)
    decoded = decode(img)
    if decoded:
        return decoded[0].data.decode('utf-8')
    return None

def detect_qr(image_path):
    content = decode_qr(image_path)
    if content:
        if content.startswith('http'):
            return detect_url(content)
        else:
            return detect_text(content)
    return "No QR code found."

# Voice Detection
def voice_to_text(model_path):
    r = sr.Recognizer()
    with sr.Microphone() as source:
        st.write("Speak now...")
        audio = r.listen(source, timeout=5)
    from vosk import Model, KaldiRecognizer
    model = Model(model_path)
    rec = KaldiRecognizer(model, 16000)
    rec.AcceptWaveform(audio.get_wav_data())
    result = json.loads(rec.FinalResult())
    return result.get('text', '')

def detect_voice(model_path):
    text = voice_to_text(model_path)
    return detect_text(text)

# Streamlit UI
st.title("Phishing & Social Engineering Detector")

input_type = st.selectbox("Choose Input", ["Text (Email/Message)", "URL", "QR Code Image", "Voice"])

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
        with open("temp.png", "wb") as f:
            f.write(uploaded.getbuffer())
        st.write(detect_qr("temp.png"))

elif input_type == "Voice":
    model_path = st.text_input("Vosk Model Path", r"C:\Users\GARIMA MANGAL\Desktop\project-1\vosk-model-small-en-us-0.15")
    if st.button("Record and Detect"):
        st.write(detect_voice(model_path))