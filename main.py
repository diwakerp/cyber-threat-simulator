import json
import requests
import subprocess
from flask import Flask, request, jsonify

# MITRE ATT&CK JSON URL
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Fetch MITRE ATT&CK data
response = requests.get(MITRE_URL)
mitre_data = response.json()

# Filter only ATT&CK techniques (exclude mitigations, groups, etc.)
techniques = [t for t in mitre_data["objects"] if t.get("type") == "attack-pattern"]

# Cyber Kill Chain stages mapping
kill_chain_mapping = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Reconnaissance",
    "initial-access": "Delivery",
    "execution": "Exploitation",
    "persistence": "Installation",
    "privilege-escalation": "Exploitation",
    "defense-evasion": "Installation",
    "credential-access": "Exploitation",
    "discovery": "Reconnaissance",
    "lateral-movement": "Command & Control",
    "collection": "Actions on Objectives",
    "exfiltration": "Actions on Objectives",
    "impact": "Actions on Objectives",
}

# CIS Controls mapping (simplified)
cis_controls = {
    "Execution": "CIS Control 8: Malware Defenses",
    "Initial Access": "CIS Control 4: Secure Configurations",
    "Privilege Escalation": "CIS Control 5: Account Control",
    "Defense Evasion": "CIS Control 8: Malware Defenses",
    "Credential Access": "CIS Control 6: Access Control",
    "Discovery": "CIS Control 7: Security Audit Logs",
    "Lateral Movement": "CIS Control 9: Network Security",
    "Collection": "CIS Control 14: Data Protection",
    "Exfiltration": "CIS Control 14: Data Protection",
    "Impact": "CIS Control 13: Incident Response"
}

# Function to map techniques to Cyber Kill Chain
def get_kill_chain_phase(technique):
    if "kill_chain_phases" in technique:
        for phase in technique["kill_chain_phases"]:
            if phase["kill_chain_name"] == "mitre-attack":
                stage = phase["phase_name"]
                return kill_chain_mapping.get(stage, "Unknown")
    
    return "Not Mapped"  

# Function to get CIS control recommendations
def get_cis_control(phase):
    return cis_controls.get(phase, "CIS Control: Not Found")

# Flask API
app = Flask(__name__)

@app.route('/attack', methods=['GET'])
def get_attack_info():
    technique_name = request.args.get("name", "").lower()

    # Initialize a list to store matching techniques
    result_techniques = []

    # Loop through all available techniques
    for technique in techniques:
        # Check if the technique name matches the search term (case-insensitive)
        if technique_name in technique["name"].lower():
            # Prepare detailed info for each matched technique
            phase = get_kill_chain_phase(technique)
            cis_control = get_cis_control(phase)
            result_techniques.append({
                "technique": technique["name"],
                "description": technique.get("description", "No description available."),
                "id": technique.get("id", "No ID available."),
                "kill_chain_phase": phase,
                "cis_control": cis_control
            })

    # Return the results if any were found
    if result_techniques:
        return jsonify(result_techniques)
    else:
        return jsonify({"error": "Technique not found"}), 404

# Function to run Nmap security scan
def run_security_scan(target):
    try:
        result = subprocess.check_output(["nmap", "-F", target], universal_newlines=True)
        return result
    except Exception as e:
        return str(e)

@app.route('/scan', methods=['GET'])
def scan_target():
    target = request.args.get("target", "localhost")
    scan_result = run_security_scan(target)
    return jsonify({"target": target, "scan_result": scan_result})

if __name__ == "__main__":
    app.run(debug=True)
