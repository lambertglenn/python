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
parser.add_argument("--role", type=str, help="Splunk role to grant write access to cloned alerts")
parser.add_argument("--disable-original", action="store_true", help="Disable original alerts after cloning")
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
def get_existing_alerts_with_sharing(app):
    """Return a dict of alert names → sharing level in the destination app."""
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    alerts = {}
    for entry in response.json()["entry"]:
        name = entry["name"]
        sharing = entry["acl"]["sharing"]
        alerts[name] = sharing
    return alerts

def get_alert_sharing(app, alert_name):
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches/{encoded_name}/acl?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json()["entry"][0]["acl"]["sharing"]

def set_alert_sharing(app, alert_name, sharing="app"):
    """Change the sharing level of an alert (e.g., from global to app)."""
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches/{encoded_name}/acl"
    payload = {
        "sharing": sharing,
        "owner": "admin"  # Optionally set owner to admin when changing sharing
    }
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 200:
        logging.info(f"🔄 Changed sharing of '{alert_name}' to '{sharing}' in app '{app}'")
    else:
        logging.warning(f"⚠️ Failed to change sharing for '{alert_name}': {response.text}")
    
def disable_alert(app, alert_name):
    """Disable the original alert in its source app."""
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches/{encoded_name}"
    payload = {"disabled": "1"}
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 200:
        logging.info(f"🚫 Disabled original alert '{alert_name}' in app '{app}'")
    else:
        logging.warning(f"⚠️ Failed to disable alert '{alert_name}': {response.text}")

def get_alert_acl(app, alert_name):
    """Fetch ACL metadata for a saved search."""
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/saved/searches/{encoded_name}/acl?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    entry = response.json()["entry"][0]
    return entry["acl"]["owner"]

def set_alert_acl(alert_name, dest_app, role, owner):
    if not owner:
        logging.warning(f"⚠️ No owner found for alert '{alert_name}', skipping ACL update")
        return
    
    """Set ACL permissions for a cloned alert."""
    encoded_name = quote(alert_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{dest_app}/saved/searches/{encoded_name}/acl"
    payload = {
        "sharing": "app",
        "owner": owner,
        "perms.read": f"*",
        "perms.write": f"admin,{role}"
    }
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 200:
        logging.info(f"🔐 ACL updated for '{alert_name}' with role '{role}'")
    else:
        logging.warning(f"⚠️ Failed to update ACL for '{alert_name}': {response.text}")

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
    existing_alerts = get_existing_alerts_with_sharing(DEST_APP)
    for app, alert_name in read_alerts_from_file(INPUT_FILE):
        sharing = existing_alerts.get(alert_name)
        if sharing == "app":
            logging.info(f"⏭️ Skipping '{alert_name}' — already exists in '{DEST_APP}' with app sharing")
            continue
        elif sharing == "global":
            logging.info(f"🔄 Changing sharing of global alert '{alert_name}' to app before cloning")
            set_alert_sharing(app, alert_name, sharing="app")        
        logging.info(f"📋 Processing alert '{alert_name}' from app '{app}'")
        try:
            config = get_alert_details(app, alert_name)
            logging.debug(f"Fetched config for '{alert_name}': {json.dumps(config, indent=2)}")
            if get_alert_sharing(app, alert_name) == "global":
                set_alert_sharing(app, alert_name, sharing="app")
            clone_alert(alert_name, config, DEST_APP, verbose=args.verbose)
            if args.disable_original:
                disable_alert(app, alert_name)
            if args.role:
                config = get_alert_details(app, alert_name)
                owner = get_alert_acl(app, alert_name)                
                set_alert_acl(alert_name, DEST_APP, role=args.role, owner=owner)
        except Exception as e:
            logging.error(f"❌ Error cloning '{alert_name}' from '{app}': {e}")

if __name__ == "__main__":
    main()