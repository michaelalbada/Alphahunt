from pathlib import Path
from typing import Dict, Any
import yaml

def load(path: str | Path) -> Dict[str, Any]:
    with open(path, "r") as fh:
        return yaml.safe_load(fh)

RECONNAISSANCE_TYPES = ["active_scan", "phishing_for_information"]
INITIAL_ACCESS_TYPES = ["content_injection", "phishing", "valid_accounts", "malware"]
EXFILTRATION_TYPES   = ["automated_exfiltration", "exfiltration_over_web", "exfiltration_over_c2_channel"]
CREDENTIAL_ACCESS_TYPES = ["password_spray", "os_credential_dumping"]
IMPACT_TYPES         = ["account_access_removal", "ransomware"]
EXECUTION_TYPES      = ["user_execution", "command_scripting_interpreter"]
LATERAL_MOVEMENT_TYPES = ["remote_services", "internal_spearphishing"]
COLLECTION_TYPES     = ["email_collection"]
COMMAND_AND_CONTROL_TYPES = ["cobalt_strike"]
PERSISTENCE_TYPES    = ["boot_or_logon_autostart_execution"]

_ATTACK_TYPE_MAP = {
    "reconnaissance":     RECONNAISSANCE_TYPES,
    "initial_access":     INITIAL_ACCESS_TYPES,
    "exfiltration":       EXFILTRATION_TYPES,
    "impact":             IMPACT_TYPES,
    "credential_access":  CREDENTIAL_ACCESS_TYPES,
    "execution":          EXECUTION_TYPES,
    "lateral_movement":   LATERAL_MOVEMENT_TYPES,
    "collection":         COLLECTION_TYPES,
    "command_and_control":COMMAND_AND_CONTROL_TYPES,
    "persistence":        PERSISTENCE_TYPES,
}

class ConfigurationError(Exception):
    pass

def load_config(path):
    with open(path, "r") as file:
        config = yaml.safe_load(file)
        return config

def validate_config(config):
    # Must have benign configuration
    if "benign" not in config:
        raise ConfigurationError("Missing 'benign' configuration in YAML file.")
    
    attacks = config.get("attacks", {})
    
    # Dictionary mapping attack types to their allowed values
    attack_type_map = {
        "reconnaissance": RECONNAISSANCE_TYPES,
        "initial_access": INITIAL_ACCESS_TYPES,
        "exfiltration": EXFILTRATION_TYPES,
        "impact": IMPACT_TYPES,
        "credential_access": CREDENTIAL_ACCESS_TYPES,
        "execution": EXECUTION_TYPES,
        "lateral_movement": LATERAL_MOVEMENT_TYPES,
        "collection": COLLECTION_TYPES,
        "command_and_control": COMMAND_AND_CONTROL_TYPES,
        "persistence": PERSISTENCE_TYPES,
    }
    
    # Validate each attack type if present in the config
    for attack_name, allowed_types in attack_type_map.items():
        attack_config = attacks.get(attack_name)
        if attack_config is not None:
            t = attack_config.get("type", allowed_types[0])  # Use first type as default
            if t not in allowed_types:
                raise ConfigurationError(f"Unsupported {attack_name} type: '{t}'")
