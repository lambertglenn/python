import argparse
import requests
import urllib3
import os
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HOST = os.getenv("SPLUNK_HOST", "https://localhost:32771")
TOKEN = os.getenv("SPLUNK_TOKEN")

def disable_alert(alert_name, app_name, session):
    alert_url = (
        f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches/{alert_name}"
        "?output_mode=json"
    )

    disable_payload = {"disabled": "1"}

    response = session.post(alert_url, data=disable_payload)

    if response.status_code == 200:
        print(f"✅ Disabled alert: {alert_name} in app: {app_name}")
    else:
        print(f"❌ Failed to disable {alert_name}: {response.status_code} - {response.text}")

def main():
    parser = argparse.ArgumentParser(
        description="Disable all alerts in a Splunk app"
    )
    parser.add_argument(
        "app_name",
        nargs="?",
        help="Name of the Splunk app to process"
    )

    args = parser.parse_args()

    # If no app name was provided, show help and exit
    if not args.app_name:
        parser.print_help()
        print("\n❌ ERROR: You must specify an app name.")
        sys.exit(1)

    app_name = args.app_name

    if not TOKEN:
        raise ValueError("Missing SPLUNK_TOKEN environment variable")

    session = requests.Session()
    session.verify = False
    session.headers.update({"Authorization": f"Splunk {TOKEN}"})

    list_url = (
        f"{SPLUNK_HOST}/servicesNS/nobody/{app_name}/saved/searches"
        "?count=0&output_mode=json"
    )

    list_response = session.get(list_url)

    print("STATUS:", list_response.status_code)
    print("RAW RESPONSE:", list_response.text[:500])  # debug

    if list_response.status_code != 200:
        raise RuntimeError(
            f"Failed to list alerts in app {app_name}: "
            f"{list_response.status_code} - {list_response.text}"
        )

    data = list_response.json()
    entries = data.get("entry", [])

    if not entries:
        print(f"ℹ️ No alerts found in app: {app_name}")
        return

    for entry in entries:
        alert_name = entry["name"]
        disable_alert(alert_name, app_name, session)


if __name__ == "__main__":
    main()
