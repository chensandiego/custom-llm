#!/var/ossec/framework/python/bin/python3
import sys
import json
import socket
import requests

# --- CONFIGURATION ---
# If Wazuh is in Docker and Ollama is on Host, use "http://host.docker.internal:11434/api/generate"
# If both are on the same metal/VM, use "http://localhost:11434/api/generate"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "mistral" 
# ---------------------

# 1. READ ALERT DATA
try:
    alert_file = sys.argv[1]
    # user and hook_url are passed by Wazuh but often unused for local integrations
    # user = sys.argv[2] 
    # hook_url = sys.argv[3]
except IndexError:
    sys.exit(1)

with open(alert_file) as f:
    alert_json = json.load(f)

# Extract log details
description = alert_json.get('rule', {}).get('description', 'N/A')
full_log = alert_json.get('full_log', 'N/A')
agent_name = alert_json.get('agent', {}).get('name', 'N/A')

# 2. CONSTRUCT PROMPT
# Keep it concise for faster local inference
prompt = (
    f"Act as a cybersecurity analyst. Review this log.\n"
    f"Rule: {description}\n"
    f"Log: {full_log}\n"
    f"Analyze: Is this benign or malicious? Explain in 2 sentences."
)

# 3. SEND TO LOCAL OLLAMA
headers = {"Content-Type": "application/json"}
data = {
    "model": OLLAMA_MODEL,
    "prompt": prompt,
    "stream": False  # CRITICAL: Wazuh expects a single response, not a stream
}

ai_output = "AI Analysis Failed"

try:
    response = requests.post(OLLAMA_URL, headers=headers, json=data, timeout=20)
    if response.status_code == 200:
        ai_output = response.json().get('response', 'No response field in JSON')
    else:
        ai_output = f"Ollama Error: {response.status_code}"
except Exception as e:
    ai_output = f"Connection Error: {str(e)}"

# 4. SEND RESPONSE BACK TO WAZUH SOCKET
socket_addr = '/var/ossec/queue/sockets/queue'

msg = {
    'version': 1,
    'origin': {
        'name': 'ollama-integration',
        'module': 'wazuh-python-integration'
    },
    'command': 'ai_check',
    'parameters': {
        'alert_id': alert_json.get('id'),
        'ai_analysis': ai_output
    }
}

# Standard Wazuh integration message format often just dumps json
# We will use the simplified injection method compatible with generic JSON decoder:
output_msg = {}
output_msg['integration'] = 'ollama'
output_msg['original_alert'] = description
output_msg['ai_analysis'] = ai_output

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.connect(socket_addr)
    # Send the combined dict
    s.send(json.dumps(output_msg).encode('utf-8'))
    s.close()
except Exception as e:
    # In production, log this to a file for debugging
    pass
