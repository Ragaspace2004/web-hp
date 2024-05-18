import re
from flask import Flask, request, redirect, render_template_string, jsonify
import datetime
import requests

app = Flask(__name__)

# Define the path for the log file
LOG_FILE = "honeypot.log"

# Define the username and password for the actual website
REAL_USERNAME = "real_username"
REAL_PASSWORD = "real_password"

# Define the Hono endpoint base URL
HONO_ENDPOINT_URL = "https://my-app.ragapriya-k2022cse.workers.dev"

# Read patterns from files
with open("ip_address.txt", "r") as f:
    ip_patterns = [line.strip() for line in f]
 
with open("usernames.txt", "r") as f:
    username_patterns = [line.strip() for line in f]

with open("passwords.txt", "r") as f:
    password_patterns = [line.strip() for line in f]

def is_valid_ip(ip):
    regex = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9][0-9]?)$')
    return regex.match(ip)

def analyze_patterns(value, patterns):
    for pattern in patterns:
        if re.match(pattern, value):
            return True
    return False

def analyze_botnet_activity(ip_address):
    HIGH_REQUEST_THRESHOLD = 100  # Requests per minute
    LARGE_PAYLOAD_SIZE = 10000  # Size in bytes

    try:
        # Fetch request frequency per minute
        response = requests.get(f"{HONO_ENDPOINT_URL}/analyze/request-frequency-per-minute/{ip_address}")
        response.raise_for_status()
        request_data = response.json()

        # Fetch max payload size
        response = requests.get(f"{HONO_ENDPOINT_URL}/analyze/size-payload/{ip_address}")
        response.raise_for_status()
        payload_data = response.json()

        # Check if request_data has valid results
        if 'results' in request_data and request_data['results']:
            high_request_count = False
            for entry in request_data['results']:
                if entry.get('request_count', 0) > HIGH_REQUEST_THRESHOLD:
                    high_request_count = True
                    break
        else:
            high_request_count = False

        # Check if payload_data has valid results
        if 'results' in payload_data and payload_data['results']:
            max_payload_size = payload_data['results'][0].get('max(payload)', 0)
        else:
            max_payload_size = 0

        if high_request_count and max_payload_size > LARGE_PAYLOAD_SIZE:
            return True, "Honeypot detected: High request frequency and large payload size"

        return False, "No botnet activity detected"

    except requests.exceptions.RequestException as e:
        print(f"Error analyzing botnet activity: {e}")
        return False, "Error analyzing botnet activity"

def botnet_analysis_2(honeypot_field):
    if honeypot_field:
        return True, "Honeypot detected"
    return False, "No honeypot activity detected"

def botnet_analysis_3(username):
    try:
        response = requests.get(f"{HONO_ENDPOINT_URL}/analyze/user-agent/{username}")
        response.raise_for_status()
        user_agent_data = response.json()

        same_usernames_count = user_agent_data['results'][0].get('COUNT(username)', 0) if user_agent_data['results'] else 0
        if same_usernames_count > 5:  # Threshold for large count
            if analyze_patterns(username, username_patterns):
                return True, "Botnet detected: Suspicious username pattern"
        return False, "No botnet activity detected"
    except requests.exceptions.RequestException as e:
        print(f"Error analyzing username activity: {e}")
        return False, "Error analyzing username activity"

def honeypot_analysis_4(ip_address):
    try:
        if analyze_patterns(ip_address, ip_patterns):
            response = requests.get(f"{HONO_ENDPOINT_URL}/analyze/request-frequency-per-minute/{ip_address}")
            response.raise_for_status()
            request_data = response.json()

            if 'results' in request_data and request_data['results']:
                high_request_count = False
                for entry in request_data['results']:
                    if entry.get('request_count', 0) > 100:  # Adjust threshold as needed
                        high_request_count = True
                        break
            else:
                high_request_count = False

            if high_request_count:
                return True, "Botnet detected: Suspicious IP address with high request frequency"
        return False, "No botnet activity detected"
    except requests.exceptions.RequestException as e:
        print(f"Error analyzing IP activity: {e}")
        return False, "Error analyzing IP activity"

def main(ip_address, honeypot_field, username):
    botnet_detected, message = analyze_botnet_activity(ip_address)
    if botnet_detected:
        return True, message

    botnet_detected, message = botnet_analysis_2(honeypot_field)
    if botnet_detected:
        return True, message

    botnet_detected, message = botnet_analysis_3(username)
    if botnet_detected:
        return True, message

    botnet_detected, message = honeypot_analysis_4(ip_address)
    if botnet_detected:
        return True, message

    return False, "No botnet activity detected"

@app.route("/", methods=["GET", "POST"])
def honeypot():
    if request.method == "POST":
        payload = request.get_data(as_text=True)

        with open("payloads.log", "a") as f:
            f.write(payload + "\n")

        username = request.form.get("username")
        password = request.form.get("password")
        honeypot_field = request.form.get("honeypot", None)
        ip_address = request.remote_addr
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Send data to the Hono endpoint
        data = {
            "username": username,
            "password": password,
            "honeypot_field": honeypot_field,
            "ip_address": ip_address,
            "timestamp": timestamp,
            "payload": payload,
            "flags": None
        }

        try:
            response = requests.post(f"{HONO_ENDPOINT_URL}/user-logs", json=data)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error sending data to Hono endpoint: {e}")
            return "Error sending data", 500

        botnet_detected, message = main(ip_address, honeypot_field, username)
        if botnet_detected:
            return render_template_string(TEMPLATE, error=message)

        if username == REAL_USERNAME and password == REAL_PASSWORD:
            return redirect("https://log-c0a.pages.dev/")
        else:
            with open(LOG_FILE, "a") as f:
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"IP Address: {ip_address}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password}\n\n")

            return render_template_string(TEMPLATE, error="Invalid username or password")
    else:
        return render_template_string(TEMPLATE, error=None)

# Define the HTML template for the login page
TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login Page</title>
<link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-200 h-screen flex justify-center items-center">
<div class="bg-white p-8 rounded-lg shadow-md max-w-xs w-full">
<h2 class="text-2xl font-bold mb-4">Login</h2>
{% if error %}
<p class="text-red-500 mb-4">{{ error }}</p>
{% endif %}
<form action="/" method="post">
<div class="mb-4">
<label for="username" class="block text-gray-700">Username:</label>
<input type="text" id="username" name="username" class="mt-1 border-2 block w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 focus:ring-opacity-50 p-2 ">
</div>
<div class="mb-4">
<label for="password" class="block text-gray-700">Password:</label>
<input type="password" id="password" name="password" class="border-2 mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:border-blue-300 focus:ring focus:ring-blue-200 p-2 focus:ring-opacity-50">
</div>
<input type="text" name="honeypot" style="display:none;">

<button type="submit" class="w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600">Submit</button>
</form>
</div>
</body>
</html>
"""

@app.route("/analyze/request-frequency/<ip_address>")
def analyze_request_frequency(ip_address):
    if not is_valid_ip(ip_address):
        return jsonify({"error": "Invalid IP address format"}), 400

    botnet_detected, message = analyze_botnet_activity(ip_address)
    if botnet_detected:
        return jsonify({"botnet_detected": True, "message": message}), 200
    else:
        return jsonify({"botnet_detected": False, "message": message}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=81)
