# SPDX-License-Identifier: 0BSD
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("aws-xfa")


def default_config_path():
    """Return the aws-xfa config path, respecting XDG_CONFIG_HOME."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "aws-xfa" / "config.json"


def load_xfa_config():
    """Load aws-xfa config from disk. Returns {} on missing or malformed."""
    path = default_config_path()
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not read aws-xfa config at %s: %s", path, e)
        return {}


def save_xfa_config(config):
    """Write aws-xfa config to disk, creating directories as needed."""
    path = default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)


def get_1pass_item(config, profile):
    """Return the 1Password item name for a profile, or None if not set."""
    try:
        return config["profiles"][profile]["onepassword_item"]
    except (KeyError, TypeError):
        return None


def set_1pass_item(config, profile, item_name):
    """Return a new config dict with the 1Password item name set."""
    profiles = dict(config.get("profiles", {}))
    profiles[profile] = dict(profiles.get(profile, {}), onepassword_item=item_name)
    return dict(config, profiles=profiles)


def get_mfa_source(config, profile):
    """Return the configured MFA source for a profile, or None if not set.

    One of 'ykman', '1password', 'prompt', or None (inferred at runtime).
    """
    try:
        return config["profiles"][profile]["mfa_source"]
    except (KeyError, TypeError):
        return None


def set_mfa_source(config, profile, source):
    """Return a new config dict with the MFA source set for a profile."""
    profiles = dict(config.get("profiles", {}))
    profiles[profile] = dict(profiles.get(profile, {}), mfa_source=source)
    return dict(config, profiles=profiles)


def get_ykman_account(config, profile):
    """Return the ykman OATH account label for a profile, or None if not set."""
    try:
        return config["profiles"][profile]["ykman_account"]
    except (KeyError, TypeError):
        return None


def set_ykman_account(config, profile, account):
    """Return a new config dict with the ykman OATH account label set."""
    profiles = dict(config.get("profiles", {}))
    profiles[profile] = dict(profiles.get(profile, {}), ykman_account=account)
    return dict(config, profiles=profiles)


def get_auth_type(config, profile):
    """Return the per-profile auth override ('sso' | 'sts'), or None to
    auto-detect at runtime."""
    try:
        return config["profiles"][profile]["auth_type"]
    except (KeyError, TypeError):
        return None


def set_auth_type(config, profile, value):
    """Return a new config dict with the auth type set for a profile."""
    profiles = dict(config.get("profiles", {}))
    profiles[profile] = dict(profiles.get(profile, {}), auth_type=value)
    return dict(config, profiles=profiles)
