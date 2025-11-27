import ollama, time

def analyze(log_text):
    return ollama.chat(
        model="mistral",
        messages=[{
            "role": "user",
            "content": f"Analyze these logs for security incidents:\n{log_text}"
        }]
    )["message"]["content"]

while True:
    with open("/var/log/auth.log") as f:
        logs = f.read()

    result = analyze(logs)
    print(result)

    time.sleep(60)
