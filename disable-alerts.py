import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load credentials from environment variables
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")
ALERT_LIST_FILE = os.getenv("SPLUNK_ALERT_LIST", "alerts.txt")

def disable_alert(alert_name, app_name, session):
    url = f"{SPLUNK_HOST}/servicesNS/{USERNAME}/{app_name}/saved/searches/{alert_name}"
    payload = {"disabled": "1"}
    response = session.post(url, data=payload)
    if response.status_code == 200:
        print(f"✅ Disabled alert: {alert_name} in app: {app_name}")
    else:
        print(f"❌ Failed for {alert_name} in {app_name}: {response.status_code} - {response.text}")

def main():
    if not USERNAME or not PASSWORD:
        raise ValueError("Missing SPLUNK_USERNAME or SPLUNK_PASSWORD environment variables")

    if not os.path.exists(ALERT_LIST_FILE):
        raise FileNotFoundError(f"Alert list file not found: {ALERT_LIST_FILE}")

    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    session.verify = False

    with open(ALERT_LIST_FILE, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != 2:
                print(f"⚠️ Skipping malformed line: {line.strip()}")
                continue
            alert_name, app_name = parts
            disable_alert(alert_name.strip(), app_name.strip(), session)

if __name__ == "__main__":
    main()