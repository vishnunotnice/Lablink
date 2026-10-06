"""Read-only service check for Vishnu's existing four-node lab."""
import json
import socket
from pathlib import Path

for node in json.loads(Path(__file__).with_name('home-lab.json').read_text())['nodes']:
    try:
        with socket.create_connection((node['ip'],node['port']),timeout=3):
            print(f"{node['name']:10} {node['ip']:15} TCP {node['port']:5} OK")
    except OSError:
        print(f"{node['name']:10} {node['ip']:15} TCP {node['port']:5} UNREACHABLE")
