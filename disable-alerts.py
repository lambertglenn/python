import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load credentials from environment variables
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:8089")
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")
ALERT_LIST_FILE = os.getenv("SPLUNK_ALERT_LIST", "alerts.txt")
APP_NAME = os.getenv("SPLUNK_APP_NAME", "search")  # Default app for alerts

def disable_alert(alert_name, session):
    url = f"{SPLUNK_HOST}/servicesNS/{USERNAME}/{APP_NAME}/saved/searches/{alert_name}"
    payload = {"disabled": "1"}
    response = session.post(url, data=payload)
    if response.status_code == 200:
        print(f"✅ Disabled alert: {alert_name}")
    else:
        print(f"❌ Failed to disable {alert_name}: {response.status_code} - {response.text}")

def main():
    if not USERNAME or not PASSWORD:
        raise ValueError("Missing SPLUNK_USERNAME or SPLUNK_PASSWORD environment variables")

    if not os.path.exists(ALERT_LIST_FILE):
        raise FileNotFoundError(f"Alert list file not found: {ALERT_LIST_FILE}")

    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    session.verify = False

    with open(ALERT_LIST_FILE, "r") as f:
        alerts = [line.strip() for line in f if line.strip()]

    for alert in alerts:
        disable_alert(alert, session)

if __name__ == "__main__":
    main()