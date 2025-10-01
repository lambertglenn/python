import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:8089")
ALERT_LIST_FILE = os.getenv("SPLUNK_ALERT_LIST", "alerts.txt")
TOKEN = os.getenv("SPLUNK_AUTH_TOKEN")

def disable_alert(alert_name, app_name, session):
    get_url = f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{alert_name}"
    disable_payload = {"disabled": "1"}
    response = session.post(get_url, data=disable_payload)
    if response.status_code == 200:
        print(f"✅ Disabled alert: {alert_name} in app: {app_name}")
    else:
        print(f"❌ Failed for {alert_name}: {response.status_code} - {response.text}")

def main():
    if not TOKEN:
        raise ValueError("Missing SPLUNK_AUTH_TOKEN environment variable")

    if not os.path.exists(ALERT_LIST_FILE):
        raise FileNotFoundError(f"Alert list file not found: {ALERT_LIST_FILE}")

    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Bearer {TOKEN}"})

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