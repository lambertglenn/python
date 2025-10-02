import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load credentials from environment variables
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://splunk.availity.net:8089")
USERNAME = os.getenv("SPLUNK_USERNAME")
PASSWORD = os.getenv("SPLUNK_PASSWORD")
APP_LIST_FILE = os.getenv("SPLUNK_APP_LIST", "apps.txt")

# ACL payload
payload = {
    "sharing": "app",  # or "app", "user"
    "owner": "admin",
    "perms.read": ["*"],
    "perms.write": ["admin"]
}

def update_app_acl(app_name, payload, session):
    url = f"{SPLUNK_HOST}/servicesNS/nobody/system/apps/local/{app_name}/acl"
    response = session.post(url, data=payload)
    if response.status_code == 200:
        print(f"✅ Updated permissions for: {app_name}")
    else:
        print(f"❌ Failed for {app_name}: {response.status_code} - {response.text}")

def main():
    if not USERNAME or not PASSWORD:
        raise ValueError("Missing SPLUNK_USERNAME or SPLUNK_PASSWORD environment variables")

    if not os.path.exists(APP_LIST_FILE):
        raise FileNotFoundError(f"App list file not found: {APP_LIST_FILE}")

    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    session.verify = False

    with open(APP_LIST_FILE, "r") as f:
        apps = [line.strip() for line in f if line.strip()]

    for app in apps:
        update_app_acl(app, payload, session)

if __name__ == "__main__":
    main()