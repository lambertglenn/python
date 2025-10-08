import os
import requests
import urllib3
from urllib.parse import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load credentials from environment variables
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")
ALERT_LIST_FILE = os.getenv("SPLUNK_ALERT_LIST", "alerts.txt")

def get_session_key(session):
    auth_url = f"{SPLUNK_HOST}/services/auth/login"
    auth_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'output_mode': 'json'
    }
    response = session.post(auth_url, data=auth_data)
    if response.status_code == 200:
        return response.json()['sessionKey']
    else:
        raise Exception(f"Authentication failed: {response.status_code} - {response.text}")

def disable_alert(alert_name, app_name, session, session_key):
    encoded_alert_name = quote(alert_name, safe='')
    disable_url = f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{encoded_alert_name}/disable"
    
    headers = {
        'Authorization': f'Splunk {session_key}',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    print(f"the url: {disable_url}")
    response = session.post(disable_url, headers=headers)
    if response.status_code == 200:
        print(f"✅ Disabled alert: {alert_name} in app: {app_name}")
    else:
        print(f"❌ Failed for {alert_name}: {response.status_code} - {response.text}")

def main():
    if not USERNAME or not PASSWORD:
        raise ValueError("Missing SPLUNK_USERNAME or SPLUNK_PASSWORD environment variables")

    if not os.path.exists(ALERT_LIST_FILE):
        raise FileNotFoundError(f"Alert list file not found: {ALERT_LIST_FILE}")

    session = requests.Session()
    session.verify = False
    
    # Get session key for authentication
    session_key = get_session_key(session)
    print(f"✅ Authenticated successfully")

    with open(ALERT_LIST_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 2:
                print(f"⚠️ Skipping malformed line: {line.strip()}")
                continue
            alert_name, app_name = parts
            disable_alert(alert_name.strip(), app_name.strip(), session, session_key)    

if __name__ == "__main__":
    main()
