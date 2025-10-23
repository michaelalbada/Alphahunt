from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any

from faker import Faker
import polars as pl

from src.benign_simulation.benign import BenignActivityGenerator
from src.attack_simulation.components.Reconnaissance.active_scanning import ActiveScanningAttackGenerator
from src.attack_simulation.components.Reconnaissance.phishing_for_information import PhishingForInformationAttackGenerator
from src.attack_simulation.components.InitialAccess.phishing import PhishingAttackGenerator
from src.attack_simulation.components.InitialAccess.content_injection import ContentInjectionAttackGenerator
from src.attack_simulation.components.InitialAccess.valid_accounts import ValidAccountsAttackGenerator
from src.attack_simulation.components.InitialAccess.initial_access_malware import InitialAccessMalwareGenerator
from src.attack_simulation.components.Exfiltration.automated_exfiltration import DataExfiltrationAttackGenerator
from src.attack_simulation.components.Exfiltration.exfiltration_over_web import ExfiltrationOverWebServiceAttackGenerator
from src.attack_simulation.components.Exfiltration.exfiltration_over_c2_channel import ExfiltrationOverC2ChannelAttackGenerator
from src.attack_simulation.components.CredentialAccess.password_spray import PasswordSprayAttackGenerator
from src.attack_simulation.components.CredentialAccess.os_credential_dumping import OSCredentialDumpingAttackGenerator
from src.attack_simulation.components.Impact.account_access_removal import AccountAccessRemovalAttackGenerator
from src.attack_simulation.components.Impact.ransomware import RansomwareAttackGenerator
from src.attack_simulation.components.Execution.user_execution import UserExecutionAttackGenerator
from src.attack_simulation.components.Execution.command_scripting_interpreter import CommandScriptingInterpreterAttackGenerator
from src.attack_simulation.components.LateralMovement.remote_services import RemoteServicesAttackGenerator
from src.attack_simulation.components.LateralMovement.internal_spearphishing import InternalSpearphishingAttackGenerator
from src.attack_simulation.components.Collection.email_collection import EmailCollectionAttackGenerator
from src.attack_simulation.components.CommandAndControl.cobalt_strike_beacon import CobaltStrikeBeaconGenerator
from src.attack_simulation.components.CommandAndControl.network_activity import NetworkActivityGenerator
from src.attack_simulation.components.Persistence.boot_logon_autostart_execution import BootLogonAutostartExecutionAttackStep

from src.utils.config import ConfigurationError

# generator utilities (used in a few attack helpers)
from src.attack_simulation.components.utils import (
    generate_device_file_events,
    generate_device_process_events,
    generate_inbound_network_events,
    generate_outbound_network_events,
    generate_device_events,
)

logger = None  # Placeholder for logger, should be initialized in the actual implementation

def generate_benign_data(benign_config):
    # Extract parameters (with defaults) from the benign section.
    num_employees = benign_config.get("num_employees", 10)
    start_date = benign_config.get("start_date", "2025-01-01")
    end_date = benign_config.get("end_date", "2025-01-02")
    num_sign_ins_per_user_min = benign_config.get("num_sign_ins_per_user_min", 1)
    num_sign_ins_per_user_max = benign_config.get("num_sign_ins_per_user_max", 5)
    num_devices_per_user_min = benign_config.get("num_devices_per_user_min", 1)
    num_devices_per_user_max = benign_config.get("num_devices_per_user_max", 3)
    device_events_per_user_min = benign_config.get("device_events_per_user_min", 1)
    device_events_per_user_max = benign_config.get("device_events_per_user_max", 5)
    device_file_events_per_user_min = benign_config.get("device_file_events_per_user_min", 1)
    device_file_events_per_user_max = benign_config.get("device_file_events_per_user_max", 5)
    device_process_events_min = benign_config.get("device_process_events_min", 1)
    device_process_events_max = benign_config.get("device_process_events_max", 5)
    emails_per_user_min = benign_config.get("emails_per_user_min", 1)
    emails_per_user_max = benign_config.get("emails_per_user_max", 5)
    network_events_per_user_min = benign_config.get("network_events_per_user_min", 1)
    network_events_per_user_max = benign_config.get("network_events_per_user_max", 5)

    benign_generator = BenignActivityGenerator(
        num_employees=num_employees,
        start_date=start_date,
        end_date=end_date,
        num_sign_ins_per_user_min=num_sign_ins_per_user_min,
        num_sign_ins_per_user_max=num_sign_ins_per_user_max,
        num_devices_per_user_min=num_devices_per_user_min,
        num_devices_per_user_max=num_devices_per_user_max,
        device_events_per_user_min=device_events_per_user_min,
        device_events_per_user_max=device_events_per_user_max,
        device_file_events_per_user_min=device_file_events_per_user_min,
        device_file_events_per_user_max=device_file_events_per_user_max,
        emails_per_user_min=emails_per_user_min,
        emails_per_user_max=emails_per_user_max,
        network_events_per_user_min=network_events_per_user_min,
        network_events_per_user_max=network_events_per_user_max,
        device_process_events_min=device_process_events_min,
        device_process_events_max=device_process_events_max,
    )  
    benign_data = benign_generator.generate_data()  
    return benign_data  

def generate_attacker():
    fake = Faker()
    attacker = {
        "AccountUpn": f"{fake.user_name()}@{fake.domain_name()}",
        "AccountDisplayName": fake.company(),
        "AccountObjectId": fake.uuid4(),
        "OnPremSid": fake.uuid4(),
        "AccountName": fake.user_name(),
        "AccountDomain": fake.domain_name(),
        "SenderIPv4": fake.ipv4(),
        "SenderIPV6": fake.ipv6(),
        "PhishingURL": fake.url(),
        "PhishingIP": fake.ipv4(),
        "ExternalServerIP": fake.ipv4(),
        "ExternalServerName": fake.domain_name(),
    }
    return attacker

def generate_reconnaissance(benign_data, attacker, recon_config):
    recon_type = recon_config.get("type", "active_scan")
    if recon_type == "active_scan":
        generator = ActiveScanningAttackGenerator(benign_data, attacker)
        recon_data, victims, last_event_time = generator.generate_active_scan()
        qa = generator.generate_question_answer_pairs()
    elif recon_type == "phishing_for_information":
        generator = PhishingForInformationAttackGenerator(benign_data, attacker)
        recon_data, victims, last_event_time = generator.generate_phishing_for_information()
        qa = generator.generate_question_answer_pairs()
    else:
        raise ConfigurationError("Unsupported reconnaissance type: '{}'".format(recon_type))
    return recon_data, victims, last_event_time, qa

def generate_initial_access(benign_data, attacker, victims, last_event_time, ia_config):
    if victims is None:
        logger.log_info("No victims from reconnaissance; skipping initial access attack.")
        return None, victims, last_event_time, None
    
    ia_type = ia_config.get("type", "content_injection")
    if ia_type == "content_injection":
        generator = ContentInjectionAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )  
        new_data, updated_victims, updated_time = generator.generate_data_content_injection_attack()
        qa = generator.generate_question_answer_pairs()
    elif ia_type == "phishing":
        generator = PhishingAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )  
        new_data, updated_victims, updated_time = generator.generate_phishing_attack()
        qa = generator.generate_question_answer_pairs()  
    elif ia_type == "valid_accounts":
        generator = ValidAccountsAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )  
        new_data, updated_victims, updated_time = generator.generate_valid_accounts_attack()  
        qa = generator.generate_question_answer_pairs()
    elif ia_type == "malware":
        generator = InitialAccessMalwareGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        new_data, updated_victims, updated_time = generator.generate_malware_transfer()
        qa = generator.generate_question_answer_pairs()
    else:  
        raise ConfigurationError("Unsupported initial access type: '{}'".format(ia_type))  
    return new_data, updated_victims, updated_time, qa  

def generate_exfiltration(benign_data, attacker, victims, last_event_time, exfil_config):
    if victims is None:
        logger.log_info("No victims available; skipping exfiltration attack.")
        return None, victims, last_event_time, None
    plausible_endpoints = exfil_config.get("plausible_endpoints")
    if not plausible_endpoints:
        raise ValueError("'plausible_endpoints' must be specified in exfiltration config.")
    exfil_type = exfil_config.get("type", "exfiltration_over_web")  
    if exfil_type == "exfiltration_over_web":  
        generator = ExfiltrationOverWebServiceAttackGenerator(
            benign_data=benign_data,  
            victims=victims,  
            attacker=attacker,  
            last_scan_time=last_event_time
        )  
        exfil_data, updated_victims, updated_time = generator.generate_exfiltration_over_web_service_attack()  
        qa = generator.generate_question_answer_pairs()  
    elif exfil_type == "automated_exfiltration":  
        generator = DataExfiltrationAttackGenerator(
            benign_data=benign_data,  
            victims=victims,  
            attacker=attacker,  
            last_scan_time=last_event_time
        )  
        exfil_data, updated_victims, updated_time = generator.generate_data_exfiltration_attack()  
        qa = generator.generate_question_answer_pairs()  
    elif exfil_type == "exfiltration_over_c2_channel":
        generator = ExfiltrationOverC2ChannelAttackGenerator(
            benign_data=benign_data,  
            victims=victims,  
            attacker=attacker,  
            last_scan_time=last_event_time,  
            plausible_endpoints=plausible_endpoints
        )
        exfil_data, updated_victims, updated_time = generator.generate_exfiltration_over_c2_channel_attack()
        qa = generator.generate_question_answer_pairs()
    else:  
        raise ConfigurationError("Unsupported exfiltration type: '{}'".format(exfil_type))  
    return exfil_data, updated_victims, updated_time, qa  

def generate_credential_access(benign_data, attacker, victims, last_event_time, credential_access_config):
    if victims is None:
        logger.log_info("No victims available; skipping credential access attack.")
        return None, victims, last_event_time, None
    
    credential_access_type = credential_access_config.get("type", "password_spray")  
    if credential_access_type == "password_spray":  
        generator = PasswordSprayAttackGenerator(
            benign_data=benign_data,  
            victims=victims,  
            attacker=attacker,  
            last_scan_time=last_event_time
        )  
        credential_access_data, updated_victims, updated_time = generator.generate_password_spray_attack()  
        qa = generator.generate_question_answer_pairs()  
    elif credential_access_type == "os_credential_dumping":
        generator = OSCredentialDumpingAttackGenerator(
            benign_data=benign_data,  
            victims=victims,  
            attacker=attacker,  
            last_scan_time=last_event_time
        )  
        credential_access_data, updated_victims, updated_time = generator.generate_os_credential_dumping_attack()  
        qa = generator.generate_question_answer_pairs()
    else:  
        raise ConfigurationError("Unsupported credential access type: '{}'".format(credential_access_type))  
    return credential_access_data, updated_victims, updated_time, qa

def generate_impact(benign_data, attacker, victims, last_event_time, impact_config):
    """Generate impact events based on type"""
    if victims is None:
        logger.log_info("No victims available; skipping impact attack.")
        return None, victims, last_event_time, None
    
    impact_type = impact_config.get("type", "account_access_removal")
    if impact_type == "ransomware":
        generator = RansomwareAttackGenerator(benign_data, victims, attacker, last_event_time)
        return generator.generate_ransomware_attack()
    elif impact_type == "account_access_removal":
        generator = AccountAccessRemovalAttackGenerator(benign_data, victims, attacker, last_event_time)
        return generator.generate_account_access_removal_attack()
    else:
        raise ValueError(f"Unknown impact type: {impact_type}")

def generate_execution(benign_data, attacker, victims, last_event_time, execution_config):
    if victims is None:
        logger.log_info("No victims available; skipping execution attack.")
        return None, victims, last_event_time, None
    
    execution_type = execution_config.get("type", "execution")
    if execution_type == "user_execution":
        generator = UserExecutionAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        execution_data, updated_victims, updated_time = generator.generate_user_execution_attack()
        qa = generator.generate_question_answer_pairs()
        return execution_data, updated_victims, updated_time, qa
    elif execution_type == "command_scripting_interpreter":
        generator = CommandScriptingInterpreterAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        execution_data, updated_victims, updated_time = generator.generate_command_scripting_attack()
        qa = generator.generate_question_answer_pairs()
        return execution_data, updated_victims, updated_time, qa
    else:
        raise ConfigurationError("Unsupported execution type: '{}'".format(execution_type))
    
def generate_lateral_movement(benign_data, attacker, victims, last_event_time, lateral_movement_config):
    if victims is None:
        logger.log_info("No victims available; skipping lateral movement attack.")
        return None, victims, last_event_time, None
    
    lateral_movement_type = lateral_movement_config.get("type", "remote_services")
    if lateral_movement_type == "remote_services":
        generator = RemoteServicesAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        lateral_movement_data, updated_victims, updated_time = generator.generate_remote_services_attack()
        qa = generator.generate_question_answer_pairs()
        return lateral_movement_data, updated_victims, updated_time, qa
    elif lateral_movement_type == "internal_spearphishing":
        generator = InternalSpearphishingAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        lateral_movement_data, updated_victims, updated_time = generator.generate_internal_spearphishing_attack()
        qa = generator.generate_question_answer_pairs()
        return lateral_movement_data, updated_victims, updated_time, qa
    else:
        raise ConfigurationError("Unsupported lateral movement type: '{}'".format(lateral_movement_type))

def generate_collection(benign_data, attacker, victims, last_event_time, collection_config):
    if victims is None:
        logger.log_info("No victims available; skipping collection attack.")
        return None, victims, last_event_time, None
    
    collection_type = collection_config.get("type", "email_collection")
    if collection_type == "email_collection":
        generator = EmailCollectionAttackGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time
        )
        collection_data, updated_victims, updated_time = generator.generate_email_collection_attack()
        qa = generator.generate_question_answer_pairs()
        return collection_data, updated_victims, updated_time, qa
    else:
        raise ConfigurationError("Unsupported collection type: '{}'".format(collection_type))
    
def generate_command_and_control(benign_data, attacker, victims, last_event_time, c2_config):
    if victims is None:
        logger.log_info("No victims available; skipping command and control attack.")
        return None, victims, last_event_time, None
    
    logger.log_info(f"DEBUG: Number of victims available for C2: {len(victims) if victims is not None else 0}")
    logger.log_info(f"DEBUG: C2 config: {c2_config}")
    
    c2_type = c2_config.get("type", "cobalt_strike")
    if c2_type == "cobalt_strike":
        generator = CobaltStrikeBeaconGenerator(
            benign_data=benign_data,
            victims=victims,
            attacker=attacker,
            last_scan_time=last_event_time,
            network_patterns=c2_config.get("network_patterns", {}),
            beacon_config=c2_config.get("beacon_config", {})
        )
        try:
            c2_data, updated_victims, updated_time = generator.generate_cobalt_strike_attack()
            qa = generator.generate_question_answer_pairs()
            return c2_data, updated_victims, updated_time, qa
        except Exception as e:
            logger.log_warning(f"DEBUG: Error generating C2 data: {str(e)}")
            return None, victims, last_event_time, None
    else:
        raise ConfigurationError("Unsupported command and control type: '{}'".format(c2_type))

def generate_persistence(benign_data, attacker, victims, last_event_time, persistence_config):
    logger.log_info(f"DEBUG: persistence_config = {persistence_config}")  # Debug print
    if victims is None:
        logger.log_info("No victims available; skipping persistence attack.")
        return None, victims, last_event_time, None

    persistence_type = persistence_config.get("type", "boot_or_logon_autostart_execution")
    if persistence_type == "boot_or_logon_autostart_execution":
        # Ensure last_scan_time is an ISO string for config serialization
        last_scan_time = last_event_time.isoformat() if isinstance(last_event_time, datetime) else last_event_time
        config = {
            "benign_data": benign_data,
            "victims": victims,
            "attacker": attacker,
            "last_scan_time": last_scan_time,
            **persistence_config  # includes common_registry_keys, etc.
        }
        generator = BootLogonAutostartExecutionAttackStep(config)
        persistence_data, updated_victims, updated_time = generator.generate_attack()
        qa = generator.generate_question_answer_pairs()
        return persistence_data, updated_victims, updated_time, qa
    else:
        raise ConfigurationError(f"Unsupported persistence type: '{persistence_type}'")
