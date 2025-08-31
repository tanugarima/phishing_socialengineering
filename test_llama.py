import ollama

# Ask the LLM a question
response = ollama.chat(model='llama3', messages=[
    {'role': 'user', 'content': 'Hello, what is phishing?'}
])

print(response['message']['content'])