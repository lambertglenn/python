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
    # Target the shared alert owned by 'nobody'
    acl_url = f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{alert_name}/acl"
    payload = {"perms.read": ["*"], "perms.write": ["admin"], "sharing": "app", "owner": "nobody"}

    # First, confirm the alert exists
    get_url = f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{alert_name}"
    get_response = session.get(get_url)
    if get_response.status_code != 200:
        print(f"❌ Alert not found or not shared: {alert_name} in {app_name}")
        return

    # Disable the alert
    disable_payload = {"disabled": "1"}
    disable_response = session.post(get_url, data=disable_payload)
    if disable_response.status_code == 200:
        print(f"✅ Disabled shared alert: {alert_name} in app: {app_name}")
    else:
        print(f"❌ Failed to disable {alert_name}: {disable_response.status_code} - {disable_response.text}")
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