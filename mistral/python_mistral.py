import ollama

model = "mistral"

logs = """
Nov 26 13:03:11 server sshd[1234]: Failed password for root from 192.168.1.88 port 44221 ssh2
Nov 26 13:03:12 server sshd[1234]: Failed password for root from 192.168.1.88 port 44221 ssh2
Nov 26 13:03:13 server sshd[1234]: Failed password for root from 192.168.1.88 port 44221 ssh2
"""

prompt = f"""
Perform security analysis on these logs:

{logs}

Identify:
- Type of attack
- Risk severity
- What the attacker might be trying
- Recommended actions
"""

response = ollama.chat(
    model=model,
    messages=[{"role": "user", "content": prompt}]
)

print(response["message"]["content"])
