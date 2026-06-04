import json
import csv
import os
from typing import Any, Dict, List

def flatten_json(y: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """
    Recursively flattens a nested JSON object.
    Example: {"a": {"b": 1}} -> {"a.b": 1}
    """
    items = []
    for k, v in y.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Convert list to string for CSV
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    return dict(items)

def json_to_csv(json_file: str, csv_file: str) -> None:
    """
    Converts a JSON file to CSV format.
    Handles both list-of-dicts and single-dict JSON structures.
    """
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"JSON file '{json_file}' not found.")

    with open(json_file, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

    # Ensure data is a list of dictionaries
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        raise ValueError("JSON must be an object or an array of objects.")

    # Flatten each JSON object
    flat_data = [flatten_json(item) for item in data]

    # Write to CSV
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=sorted({k for d in flat_data for k in d.keys()}))
        writer.writeheader()
        writer.writerows(flat_data)

    print(f"✅ Successfully converted '{json_file}' to '{csv_file}'.")

if __name__ == "__main__":
    # Example usage
    try:
        json_to_csv("input.json", "output.csv")
    except Exception as e:
        print(f"❌ Error: {e}")
