#!/usr/bin/env python3
"""Create the runtime Samba AD configuration without storing passwords in Git."""

import json
import os
from pathlib import Path


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"required environment variable {name} is unset")
    return value


template_path = Path(os.environ["SAMBACC_CONFIG_TEMPLATE"])
runtime_path = Path("/tmp/netraze-domain.json")
config = json.loads(template_path.read_text(encoding="utf-8"))

config["domain_settings"]["netraze"]["admin_password"] = required(
    "NETRAZE_SAMBA_AD_ADMIN_PASSWORD"
)
user_password = required("NETRAZE_SAMBA_AD_PASSWORD")
for user in config["domain_users"]["netraze"]:
    user["password"] = user_password

runtime_path.write_text(json.dumps(config), encoding="utf-8")
runtime_path.chmod(0o600)
os.environ["SAMBACC_CONFIG"] = str(runtime_path)
os.execvp(
    "samba-dc-container",
    ["samba-dc-container", "run", "--setup=provision", "--setup=populate"],
)
