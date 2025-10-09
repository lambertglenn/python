import os
import argparse
import logging
import requests
import json
from urllib.parse import quote

# --- ENVIRONMENT VARIABLES ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() == "true"

# --- HEADERS ---
HEADERS = {
    "Authorization": f"Bearer {SPLUNK_TOKEN}",
    "Content-Type": "application/json"
}

if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 📥 Read dashboards from input file
def read_dashboards_from_file(path):
    """Yield (app, dashboard_name) tuples from input file."""
    with open(path, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                yield parts[0].strip(), parts[1].strip()

# 📋 Get existing dashboards in destination app
def list_existing_dashboards(app):
    """Return a set of dashboard names already present in the destination app."""
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/data/ui/views?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return {entry["name"] for entry in response.json()["entry"]}

# 📄 Get dashboard XML
def get_dashboard_xml(app, dashboard_name):
    encoded_name = quote(dashboard_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/data/ui/views/{encoded_name}?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json()["entry"][0]["content"]["eai:data"]

# 👤 Get dashboard owner
def get_dashboard_owner(app, dashboard_name):
    encoded_name = quote(dashboard_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{app}/data/ui/views/{encoded_name}/acl?output_mode=json"
    response = requests.get(url, headers=HEADERS, verify=VERIFY_SSL)
    response.raise_for_status()
    return response.json()["entry"][0]["acl"]["owner"]

# 📦 Clone dashboard
def clone_dashboard(dashboard_name, xml, dest_app, verbose=False):
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{dest_app}/data/ui/views"
    payload = {
        "name": dashboard_name,
        "eai:data": xml,
        "output_mode": "json"
    }
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    if verbose:
        logging.info(f"📦 Cloning dashboard '{dashboard_name}' into '{dest_app}'")
        logging.debug(json.dumps(payload, indent=2))

    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 201:
        logging.info(f"✅ Cloned dashboard '{dashboard_name}'")
    else:
        raise Exception(f"Failed to clone '{dashboard_name}': {response.text}")

# 🔐 Set ACL
def set_dashboard_acl(dashboard_name, dest_app, role, owner):
    encoded_name = quote(dashboard_name, safe='')
    url = f"{SPLUNK_HOST}/servicesNS/nobody/{dest_app}/data/ui/views/{encoded_name}/acl"
    payload = {
        "sharing": "app",
        "owner": owner,
        "perms.read": f"user,admin,{role}",
        "perms.write": f"admin,{role}"
    }
    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(url, headers=headers, data=payload, verify=VERIFY_SSL)
    if response.status_code == 200:
        logging.info(f"🔐 ACL updated for '{dashboard_name}' with owner '{owner}' and role '{role}'")
    else:
        logging.warning(f"⚠️ Failed to update ACL for '{dashboard_name}': {response.text}")

# 🚀 Main
def main(args):
    existing_dashboards = list_existing_dashboards(args.dest_app)

    for app, dashboard_name in read_dashboards_from_file(args.input_file):
        if dashboard_name in existing_dashboards:
            logging.info(f"⏭️ Skipping '{dashboard_name}' — already exists in '{args.dest_app}'")
            continue
        try:
            xml = get_dashboard_xml(app, dashboard_name)
            owner = get_dashboard_owner(app, dashboard_name)
            clone_dashboard(dashboard_name, xml, args.dest_app, verbose=args.verbose)
            if args.role:
                set_dashboard_acl(dashboard_name, args.dest_app, args.role, owner)
        except Exception as e:
            logging.error(f"❌ Error cloning '{dashboard_name}' from '{app}': {e}")

# 🧵 CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clone Splunk dashboards between apps")
    parser.add_argument("--input-file", required=True, help="CSV file with source_app,dashboard_name")
    parser.add_argument("--dest-app", required=True, help="Destination Splunk app")
    parser.add_argument("--role", help="Splunk role to grant write access")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--logfile", help="Log file path")

    args = parser.parse_args()
    VERBOSE = args.verbose
    LOG_FILE = args.logfile

    # --- LOGGING SETUP ---
import sys

log_level = logging.DEBUG if args.verbose else logging.INFO
log_format = "%(asctime)s %(levelname)s %(message)s"

if args.logfile:
    logging.basicConfig(
        level=log_level,
        format=log_format,
        filename=args.logfile,
        filemode="a"
    )
else:
    logging.basicConfig(
        level=log_level,
        format=log_format,
        stream=sys.stdout
    )

    main(args)