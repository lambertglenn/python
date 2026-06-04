import argparse
import requests
import urllib3
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
TOKEN = os.getenv("SPLUNK_TOKEN")


def disable_alert(alert_name, app_name, session):
    """Disable a single alert if it is enabled."""
    alert_url = (
        f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{alert_name}"
        "?output_mode=json"
    )

    # Fetch alert details
    get_resp = session.get(alert_url)
    if get_resp.status_code != 200:
        print(f"❌ Failed to fetch {alert_name}: {get_resp.status_code}")
        return False

    alert_data = get_resp.json()
    content = alert_data["entry"][0]["content"]

    # Check enabled/disabled state
    is_disabled = content.get("disabled", False)

    if is_disabled:
        print(f"⏭️  Skipped (already disabled): {alert_name}")
        return False

    # Disable the alert
    disable_payload = {"disabled": "1"}
    post_resp = session.post(alert_url, data=disable_payload)

    if post_resp.status_code == 200:
        print(f"✅ Disabled alert: {alert_name}")
        return True
    else:
        print(f"❌ Failed to disable {alert_name}: {post_resp.status_code} - {post_resp.text}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Disable all alerts in a Splunk app")
    parser.add_argument("app_name", nargs="?", help="Name of the Splunk app to process")
    args = parser.parse_args()

    if not args.app_name:
        parser.print_help()
        print("\n❌ ERROR: You must specify an app name.")
        sys.exit(1)

    app_name = args.app_name

    if not TOKEN:
        raise ValueError("Missing SPLUNK_AUTH_TOKEN environment variable")

    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Splunk {TOKEN}"})

    # List all alerts in the app
    list_url = (
        f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches"
        "?count=0&output_mode=json"
    )
    list_resp = session.get(list_url)

    if list_resp.status_code != 200:
        raise RuntimeError(
            f"Failed to list alerts in app {app_name}: "
            f"{list_resp.status_code} - {list_resp.text}"
        )

    data = list_resp.json()
    entries = data.get("entry", [])

    if not entries:
        print(f"ℹ️ No alerts found in app: {app_name}")
        return

    disabled_count = 0

    for entry in entries:
        alert_name = entry["name"]
        if disable_alert(alert_name, app_name, session):
            disabled_count += 1

    print("\n==============================")
    print(f"🔢 Total alerts disabled: {disabled_count}")
    print("==============================")


if __name__ == "__main__":
    main()
