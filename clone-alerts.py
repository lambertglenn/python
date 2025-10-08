import os
import requests
import json
import logging
from urllib.parse import quote

# --- ENVIRONMENT VARIABLES ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
INPUT_FILE = os.getenv("ALERT_INPUT_FILE", "alerts_to_clone.csv")
DEST_APP = os.getenv("DEST_APP")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# --- VALIDATION ---
if not SPLUNK_TOKEN or not DEST_APP:
    raise ValueError("Missing required environment variables: SPLUNK_TOKEN and DEST_APP")

# --- LOGGING SETUP ---
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# --- HEADERS ---
HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

# --- FUNCTIONS ---
def read_alerts_from_file(filename):
    """Read app and alert name pairs from a CSV-style file."""
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) == 2:
                yield parts[0].strip(), parts[1].strip()

def get_alert_details(app, alert_name):
    """Fetch full alert configuration."""
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches/{encoded_name}?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json()["entry"][0]["content"]

def clone_alert(alert_name, alert_config, dest_app):
    """Clone alert into destination app."""
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{dest_app}/saved/searches"
    payload = {k: v for k, v in alert_config.items() if not k.startswith("eai:")}
    payload["name"] = alert_name
    response = requests.post(url, headers=HEADERS, data=json.dumps(payload), verify=VERIFY_SSL)
    if response.status_code == 201:
        logging.info(f"✅ Cloned alert '{alert_name}' into '{dest_app}'")
    else:
        logging.warning(f"⚠️ Failed to clone '{alert_name}': {response.text}")

# --- MAIN EXECUTION ---
def main():
    for app, alert_name in read_alerts_from_file(INPUT_FILE):
        logging.info(f"📋 Processing alert '{alert_name}' from app '{app}'")
        try:
            config = get_alert_details(app, alert_name)
            clone_alert(alert_name, config, DEST_APP)
        except Exception as e:
            logging.error(f"❌ Error cloning '{alert_name}' from '{app}': {e}")

if __name__ == "__main__":
    main()