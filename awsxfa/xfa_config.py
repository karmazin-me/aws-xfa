# SPDX-License-Identifier: 0BSD
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger('aws-xfa')


def default_config_path():
    """Return the aws-xfa config path, respecting XDG_CONFIG_HOME."""
    xdg_config = os.environ.get('XDG_CONFIG_HOME')
    base = Path(xdg_config) if xdg_config else Path.home() / '.config'
    return base / 'aws-xfa' / 'config.json'


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
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)


def get_1pass_item(config, profile):
    """Return the 1Password item name for a profile, or None if not set."""
    try:
        return config['profiles'][profile]['onepassword_item']
    except (KeyError, TypeError):
        return None


def set_1pass_item(config, profile, item_name):
    """Return a new config dict with the 1Password item name set."""
    profiles = dict(config.get('profiles', {}))
    profiles[profile] = dict(profiles.get(profile, {}),
                             onepassword_item=item_name)
    return dict(config, profiles=profiles)
