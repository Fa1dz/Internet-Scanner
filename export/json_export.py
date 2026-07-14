import json


def export_devices_json(path, devices):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(devices, f, indent=2, default=str)
