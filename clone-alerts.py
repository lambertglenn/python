import os
import requests
import json
import logging
from urllib.parse import quote
import argparse

# --- CLI ARGUMENTS ---
parser = argparse.ArgumentParser(description="Clone Splunk alerts from source apps into a target app.")
parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
parser.add_argument("--logfile", type=str, default="clone_alerts.log", help="Path to log file")
args = parser.parse_args()

VERBOSE = args.verbose
LOG_FILE = args.logfile

# --- ENVIRONMENT VARIABLES ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
INPUT_FILE = os.getenv("ALERT_INPUT_FILE", "alerts_to_clone.csv")
DEST_APP = os.getenv("DEST_APP")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- VALIDATION ---
if not SPLUNK_TOKEN or not DEST_APP:
    raise ValueError("Missing required environment variables: SPLUNK_TOKEN and DEST_APP")

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- HEADERS ---
HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

# --- FUNCTIONS ---
def list_existing_alerts(app):
    """Return a set of alert names already present in the destination app."""
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return {entry["name"] for entry in response.json()["entry"]}

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

def clone_alert(alert_name, alert_config, dest_app, verbose=False):
    """Clone alert into destination app, with optional verbose logging."""
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{dest_app}/saved/searches"

    ALLOWED_KEYS = [
        "name", "search", "alert_type", "alert_comparator", "alert_threshold",
        "alert_condition", "alert_digest_mode", "alert_expires", "alert_managed_by",
        "alert_severity", "alert_suppress", "alert_suppress_period", "alert_track",
        "cron_schedule", "disabled", "dispatch.earliest_time", "dispatch.latest_time",
        "is_scheduled", "description", "actions", "action.email.to", "action.email.subject",
        "action.email.message", "action.email.sendresults", "action.email.inline",
        "action.email.format", "action.email.useNSSubject", "action.email.useNSMessage",
        "action.email.sendpdf", "action.email.pdfview"
    ]

    payload = {
        k: str(v) for k, v in alert_config.items()
        if k in ALLOWED_KEYS and v is not None
    }
    payload["name"] = alert_name

    if verbose:
        logging.info(f"🔍 Verbose: alert config for '{alert_name}':")
        logging.debug(json.dumps(alert_config, indent=2))
        logging.info(f"📦 Payload to POST:")
        logging.debug(json.dumps(payload, indent=2))

    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 201:
        logging.info(f"✅ Cloned alert '{alert_name}' into '{dest_app}'")
    else:
        logging.warning(f"⚠️ Failed to clone '{alert_name}': {response.status_code} - {response.text}")
        
# --- MAIN EXECUTION ---
def main():
    existing_alerts = list_existing_alerts(DEST_APP)
    for app, alert_name in read_alerts_from_file(INPUT_FILE):
        logging.info(f"📋 Processing alert '{alert_name}' from app '{app}'")
        try:
            if alert_name in existing_alerts:
                logging.info(f"⏭️ Skipping '{alert_name}' — already exists in '{DEST_APP}'")
                continue
            config = get_alert_details(app, alert_name)
            logging.debug(f"Fetched config for '{alert_name}': {json.dumps(config, indent=2)}")
            clone_alert(alert_name, config, DEST_APP, verbose=args.verbose)
        except Exception as e:
            logging.error(f"❌ Error cloning '{alert_name}' from '{app}': {e}")

if __name__ == "__main__":
    main()