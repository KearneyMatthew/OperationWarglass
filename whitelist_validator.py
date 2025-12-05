#
#   whitelist_validator.py
#   Loads whitelist.yaml (the policy you provided) and provides validation and safe command-building for
#   Codellama-proposed actions.
#   required to be used if going through ssh_exec.py
#
#   Usage:
#    from whitelist_validator import validate_and_build
#
#    action = {
#        "tool": "nmap",
#        "params": {
#            "target": "192.168.60.3",
#            "flags": "-sV",
#            "ports": "-p 22,80"
#        }
#    }
#    cmd, meta = validate_and_build(action)  # cmd is a safe string, meta contains metadata
#

import os
import re
import yaml
import ipaddress
from typing import Tuple, Dict, Any

# Path to whitelist file (Must be in the same directory as this script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WL_PATH = os.path.join(BASE_DIR, "whitelist.yaml")

# Load YAML once
if not os.path.exists(WL_PATH):
    raise FileNotFoundError(f"Whitelist file not found at {WL_PATH}")

with open(WL_PATH, "r") as f:
    WL = yaml.safe_load(f)

# Basic validator


def is_valid_ip(val: str) -> bool:
    """Return True if val is a valid IPv4 dotted quad."""
    try:
        ipaddress.IPv4Address(val)
        return True
    except Exception:
        return False


def sanitize_alnum(val: str, max_len: int = 128) -> str:
    """Allow only alphanumeric, underscore, hyphen (safe for usernames/labels)."""
    if not isinstance(val, str):
        raise ValueError("value must be a string")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,%d}" % max_len, val):
        raise ValueError("invalid alnum value")
    return val


def sanitize_ports(val: str) -> str:
    """Allow digits, commas and hyphens (e.g. '22,80' or '1-1024'). Returns a prefixed '-p <list>' string suitable for template substitution."""
    if not isinstance(val, str):
        raise ValueError("ports must be a string")
    if not re.fullmatch(r"[0-9,\-]+", val):
        raise ValueError("invalid ports format")
    # prefix with -p so templates can simply use {ports}
    return f"-p {val}"


def sanitize_int(val: Any, min_v: int = None, max_v: int = None) -> str:
    """Convert to int and check bounds; return string form for template substitution."""
    try:
        v = int(val)
    except Exception:
        raise ValueError("value is not an integer")
    if min_v is not None and v < min_v:
        raise ValueError("integer value below minimum")
    if max_v is not None and v > max_v:
        raise ValueError("integer value above maximum")
    return str(v)


def check_allowed_path(path: str, allowed_paths: list) -> str:
    """Only allow exact allowed_paths entries (no arbitrary path traversal)."""
    if path in allowed_paths:
        return path
    raise ValueError("path not in allowed paths")


def check_enum(val: str, allowed: list) -> str:
    """Ensure val is one of allowed enum values."""
    if val in allowed:
        return val
    raise ValueError("enum value not allowed")


def check_iface(val: str, allowed: list) -> str:
    """Ensure interface is one of the allowed interface names."""
    if val in allowed:
        return val
    raise ValueError("interface not allowed")


# safe blacklist definitions
BLACKLIST_TOKENS = [
    ";", "&&", "|", ">", "<", "$(", "$",
    "rm", "shutdown", "reboot"
]

def assert_no_blacklist(cmd: str):
    """Raise ValueError if command contains suspicious tokens.

    - Skips empty tokens (defensive).
    - Uses word-boundary checks for alpha tokens like 'rm', 'shutdown', 'reboot'
      so substrings inside safe words won't falsely trigger.
    - Uses simple 'in' checks for symbol tokens.
    """
    low = cmd.lower()

    for tok in BLACKLIST_TOKENS:
        if not tok:
            # defensive: skip for now
            continue

        # word-like tokens
        if re.fullmatch(r"[a-zA-Z]+", tok):
            if re.search(r"\b" + re.escape(tok) + r"\b", low):
                raise ValueError(f"final command contains disallowed token: {tok}")
        else:
            # symbols / special sequences
            if tok in low:
                raise ValueError(f"final command contains disallowed token: {tok}")


#
#   Core job
#
def validate_and_build(action: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Validate an action dict against whitelist.yaml and build a safe command string.

    Parameters:
        action: dict, expected to include:
            - "tool": tool name (string)
            - either "params": dict of parameters, OR parameters present at top level of action

    Returns:
        (command_string, metadata_dict)

    Raises:
        ValueError with human-readable message on validation failure.
    """
    if not isinstance(action, dict):
        raise ValueError("action must be a dict")

    tool_name = action.get("tool")
    if not tool_name:
        raise ValueError("action missing required 'tool' field")

    # Lookup tool
    tools = WL.get("tools", {})
    tool_meta = tools.get(tool_name)
    if not tool_meta:
        raise ValueError(f"Tool '{tool_name}' not allowed")

    # Use nested params to top-level keys
    params = action.get("params", {})
    if not isinstance(params, dict):
        # if params is not present or not a dict, treat top-level keys as params
        params = {k: v for k, v in action.items() if k != "tool"}

    # Validate each parameter according to the whitelist
    validated: Dict[str, str] = {}
    params_meta = tool_meta.get("params", [])
    for pmeta in params_meta:
        pname = pmeta.get("name")
        prequired = pmeta.get("required", False)
        ptype = pmeta.get("type", "string")  # default

        if pname not in params:
            if prequired:
                raise ValueError(f"Missing required parameter: '{pname}'")
            else:
                continue  # optional param missing is alllllrrrrrright

        raw_val = params[pname]

        if ptype == "ip":
            if not isinstance(raw_val, str) or not is_valid_ip(raw_val):
                raise ValueError(f"Invalid IP for parameter '{pname}': {raw_val}")
            validated[pname] = raw_val
        elif ptype == "cidr":
            if not isinstance(raw_val, str):
                raise ValueError(f"CIDR parameter '{pname}' must be a string")
            import ipaddress
            try:
                # Accepts both IPs and CIDR ranges
                ipaddress.ip_network(raw_val, strict=False)
            except Exception:
                try:
                    ipaddress.ip_address(raw_val)
                except Exception:
                    raise ValueError(f"Invalid CIDR/IP for parameter '{pname}': {raw_val}")
            validated[pname] = raw_val
        elif ptype == "alnum":
            validated[pname] = sanitize_alnum(raw_val)
        elif ptype == "ports":
            validated[pname] = sanitize_ports(raw_val)
        elif ptype == "int":
            min_v = pmeta.get("min")
            max_v = pmeta.get("max")
            validated[pname] = sanitize_int(raw_val, min_v, max_v)
        elif ptype == "existing_path":
            allowed_paths = pmeta.get("allowed_paths", [])
            validated[pname] = check_allowed_path(raw_val, allowed_paths)
        elif ptype == "enum":
            allowed = pmeta.get("allowed", [])
            validated[pname] = check_enum(raw_val, allowed)
        elif ptype == "iface":
            allowed = pmeta.get("allowed", [])
            validated[pname] = check_iface(raw_val, allowed)
        else:
            if not isinstance(raw_val, str):
                raise ValueError(f"Parameter '{pname}' must be a string")
            if not re.fullmatch(r"[A-Za-z0-9_\-./]+", raw_val):
                raise ValueError(f"Parameter '{pname}' contains invalid characters")
            validated[pname] = raw_val

    # Build command template
    template = tool_meta.get("template", "")
    if not template:
        raise ValueError(f"No template defined for tool '{tool_name}'")

    cmd = template
    for k, v in validated.items():
        cmd = cmd.replace("{" + k + "}", str(v))

    # Remove any placeholders
    cmd = re.sub(r"\{\w+\}", "", cmd)
    # Normalize whitespace
    cmd = re.sub(r"\s+", " ", cmd).strip()

    # LAST safety check
    assert_no_blacklist(cmd)

    metadata = {
        "tool": tool_name,
        "requires_approval": bool(tool_meta.get("requires_approval", False)),
        "template": template,
        "validated_params": validated,
    }

    return cmd, metadata


# wrapper
def build_command(action: Dict[str, Any]) -> str:
    """Backwards-compatible wrapper that returns only the command string. Tip Raises ValueError on failure."""
    cmd, _meta = validate_and_build(action)
    return cmd


# Quick test
if __name__ == "__main__":
    tests = [
        {"tool": "nmap", "params": {"target": "192.168.60.3", "flags": "-sV"}},
        {"tool": "ping", "target": "192.168.60.3"},  # top-level params style
        {"tool": "tcpdump", "params": {"interface": "eth1", "duration": 10}},
        {"tool": "blue_detection_agent", "params": {"script": "blue_detection_agent.py"}},
    ]
    for t in tests:
        try:
            cmd, meta = validate_and_build(t)
            print("OK:", t, "->", cmd, " meta:", meta)
        except Exception as e:
            print("ERR:", t, "->", e)
