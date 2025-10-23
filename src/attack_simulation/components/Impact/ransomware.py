import random
from datetime import datetime, timedelta
import polars as pl
from faker import Faker
from tqdm import tqdm
from typing import Dict, List, Tuple, Any

from ..utils import (
    generate_device_file_events,
    generate_device_process_events,
    generate_inbound_network_events,
    generate_outbound_network_events,
    generate_device_events
)

class RansomwareAttackGenerator:
    """Generator for ransomware attack events (T1486: Data Encrypted for Impact)"""
    
    def __init__(self, benign_data: Dict[str, pl.DataFrame], victims: List[Dict[str, Any]], 
                 attacker: Dict[str, str], last_scan_time: datetime, config: dict = None):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.attacker = attacker
        self.config = config or {}
        
        # Ransomware specific configurations (from config if present)
        ransomware_cfg = (self.config.get('impact', {}) or {}).get('ransomware', {})
        self.encryption_extensions = ransomware_cfg.get('encryption_extensions', ['.encrypted', '.locked', '.crypted', '.locked1', '.crypt'])
        self.target_directories = ransomware_cfg.get('target_directories', ['Documents', 'Desktop', 'Pictures', 'Videos', 'Downloads'])
        self.ransom_note_names = ransomware_cfg.get('ransom_note_names', ['README.txt', 'DECRYPT.html', 'HELP.html', 'HOW_TO_DECRYPT.txt'])
        self.file_types_to_encrypt = ransomware_cfg.get('file_types_to_encrypt', ['.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.txt'])
        self.encryption_processes = ransomware_cfg.get('encryption_processes', ['ransomware.exe', 'cryptor.exe', 'winlock.exe', 'encryptor.exe'])
        self.ransom_note_templates = ransomware_cfg.get('ransom_note_templates', [
            "Your files have been encrypted. To decrypt them, follow the instructions in this file.",
            "All your important files have been encrypted. Contact us to get the decryption key.",
            "Your files are now encrypted. Payment required for decryption key."
        ])

        # Cobalt Strike specific configurations (from config if present)
        cobalt_cfg = ransomware_cfg.get('cobalt_strike', {})
        self.cobalt_strike_config = {
            "team_server": cobalt_cfg.get("team_server", "https://c2.example.com"),
            "profile": cobalt_cfg.get("profile", "default.profile"),
            "beacon_type": cobalt_cfg.get("beacon_type", "http"),
            "sleep_time": cobalt_cfg.get("sleep_time", 60),
            "jitter": cobalt_cfg.get("jitter", 20),
            "processes": cobalt_cfg.get("processes", ['beacon.exe', 'csrss.exe', 'dllhost.exe', 'svchost.exe']),
            "ports": cobalt_cfg.get("ports", [80, 443, 8080]),
            "user_agents": cobalt_cfg.get("user_agents", [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
            ]),
            "uri_patterns": cobalt_cfg.get("uri_patterns", ["/jquery-3.3.1.min.js", "/bootstrap.min.css", "/api/v1/check", "/updates/check.php"]),
            "beacon_intervals": cobalt_cfg.get("beacon_intervals", [60, 120, 180, 300])
        }

        # Randomization parameters (from config if present)
        rand_cfg = ransomware_cfg.get('randomization', {})
        self.rand_beacon_events_min = rand_cfg.get('beacon_events_min', 5)
        self.rand_beacon_events_max = rand_cfg.get('beacon_events_max', 15)
        self.rand_files_to_encrypt_min = rand_cfg.get('files_to_encrypt_min', 5)
        self.rand_files_to_encrypt_max = rand_cfg.get('files_to_encrypt_max', 15)
        self.rand_c2_beacon_events_min = rand_cfg.get('c2_beacon_events_min', 3)
        self.rand_c2_beacon_events_max = rand_cfg.get('c2_beacon_events_max', 7)
        self.rand_file_encrypt_interval_min = rand_cfg.get('file_encrypt_interval_min', 1)
        self.rand_file_encrypt_interval_max = rand_cfg.get('file_encrypt_interval_max', 3)
        self.rand_ransom_note_interval_min = rand_cfg.get('ransom_note_interval_min', 1)
        self.rand_ransom_note_interval_max = rand_cfg.get('ransom_note_interval_max', 2)

    def generate_cobalt_strike_events(self, victim: Dict[str, Any], start_time: datetime) -> List[Dict[str, Any]]:
        """Generate Cobalt Strike beacon activity events"""
        events = []
        current_time = start_time
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Generate multiple beacon events
        for _ in range(random.randint(self.rand_beacon_events_min, self.rand_beacon_events_max)):
            event = generate_outbound_network_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=current_time,
                fake=self.fake,
                remote_ip=self.attacker["ExternalServerIP"],
                remote_url=f"https://{self.attacker['ExternalServerName']}{random.choice(self.cobalt_strike_config['uri_patterns'])}",
                remote_port=random.choice(self.cobalt_strike_config["ports"])
            )
            events.append(event)
            current_time += timedelta(seconds=random.choice(self.cobalt_strike_config['beacon_intervals']))
            
        return events

    def generate_file_encryption_events(self, victim: Dict[str, Any], start_time: datetime) -> List[Dict[str, Any]]:
        """Generate file encryption events for a victim"""
        events = []
        current_time = start_time
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Generate file encryption events for each target directory
        for directory in self.target_directories:
            # Simulate scanning and encrypting files
            for _ in range(random.randint(self.rand_files_to_encrypt_min, self.rand_files_to_encrypt_max)):  # Number of files to encrypt
                file_name = f"{self.fake.word()}{random.choice(self.file_types_to_encrypt)}"
                encrypted_name = f"{file_name}{random.choice(self.encryption_extensions)}"
                file_path = f"C:\\Users\\{victim['AccountName']}\\{directory}\\{file_name}"
                encrypted_path = f"C:\\Users\\{victim['AccountName']}\\{directory}\\{encrypted_name}"
                process_name = random.choice(self.encryption_processes)
                process_id = random.randint(1000, 9999)
                file_size = random.randint(1000, 10000000)
                
                # File access event
                events.append(generate_device_file_events(
                    identity_row=victim,
                    device_row=device_info,
                    timestamp=current_time,
                    fake=self.fake,
                    file_name=file_name,
                    file_path=f"C:\\Users\\{victim['AccountName']}\\{directory}"
                ))
                
                # File modification event (encryption)
                events.append(generate_device_file_events(
                    identity_row=victim,
                    device_row=device_info,
                    timestamp=current_time + timedelta(seconds=random.randint(self.rand_file_encrypt_interval_min, self.rand_file_encrypt_interval_max)),
                    fake=self.fake,
                    file_name=encrypted_name,
                    file_path=f"C:\\Users\\{victim['AccountName']}\\{directory}"
                ))
                
                current_time += timedelta(seconds=random.randint(self.rand_file_encrypt_interval_min, self.rand_file_encrypt_interval_max))
        
        return events

    def generate_ransom_note_events(self, victim: Dict[str, Any], start_time: datetime) -> List[Dict[str, Any]]:
        """Generate ransom note creation events"""
        events = []
        current_time = start_time
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Create ransom notes in multiple locations
        for note_name in self.ransom_note_names:
            for directory in self.target_directories:
                process_name = random.choice(self.encryption_processes)
                process_id = random.randint(1000, 9999)
                file_size = random.randint(100, 1000)
                
                events.append(generate_device_file_events(
                    identity_row=victim,
                    device_row=device_info,
                    timestamp=current_time,
                    fake=self.fake,
                    file_name=note_name,
                    file_path=f"C:\\Users\\{victim['AccountName']}\\{directory}"
                ))
                current_time += timedelta(seconds=random.randint(self.rand_ransom_note_interval_min, self.rand_ransom_note_interval_max))
        
        return events

    def generate_process_events(self, victim: Dict[str, Any], start_time: datetime) -> List[Dict[str, Any]]:
        """Generate process events for ransomware execution"""
        events = []
        current_time = start_time
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Initial process creation
        process_name = random.choice(self.encryption_processes)
        process_command_line = f"C:\\Windows\\System32\\{process_name} -k netsvcs"
        
        events.append(generate_device_process_events(
            identity_row=victim,
            device_row=device_info,
            timestamp=current_time,
            fake=self.fake,
            file_name=process_name,
            process_command_line=process_command_line
        ))
        
        return events

    def generate_network_events(self, victim: Dict[str, Any], start_time: datetime) -> List[Dict[str, Any]]:
        """Generate network events for C2 communication"""
        events = []
        current_time = start_time
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Generate C2 beacon events
        for _ in range(random.randint(self.rand_c2_beacon_events_min, self.rand_c2_beacon_events_max)):
            event = generate_outbound_network_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=current_time,
                fake=self.fake,
                remote_ip=self.attacker["ExternalServerIP"],
                remote_url=self.attacker["ExternalServerName"],
                remote_port=random.choice([443, 8080, 4444])
            )
            events.append(event)
            current_time += timedelta(seconds=random.randint(30, 60))
        
        return events

    def generate_ransomware_attack(self) -> Tuple[Dict[str, pl.DataFrame], List[Dict[str, Any]], datetime, pl.DataFrame]:
        """Generate all events related to ransomware activity"""
        all_file_events = []
        all_process_events = []
        all_network_events = []
        current_time = self.last_scan_time
        
        victims_list = self.victims.to_dicts()
        for victim in victims_list:
            # Generate Cobalt Strike events
            cobalt_strike_events = self.generate_cobalt_strike_events(victim, current_time)
            
            # Generate ransomware events
            file_events = self.generate_file_encryption_events(victim, current_time)
            ransom_note_events = self.generate_ransom_note_events(victim, current_time)
            process_events = self.generate_process_events(victim, current_time)
            network_events = self.generate_network_events(victim, current_time)
            
            all_file_events.extend(file_events + ransom_note_events)
            all_process_events.extend(process_events)
            all_network_events.extend(cobalt_strike_events + network_events)
            
            # Update the last event time
            event_times = []
            for e in file_events + ransom_note_events + process_events + cobalt_strike_events + network_events:
                ts = e["Timestamp"]
                if isinstance(ts, str):
                    event_times.append(datetime.fromisoformat(ts))
                else:
                    event_times.append(ts)
            if event_times:
                current_time = max(event_times)
        
        # Convert to polars DataFrames
        file_df = pl.DataFrame(all_file_events) if all_file_events else pl.DataFrame()
        process_df = pl.DataFrame(all_process_events) if all_process_events else pl.DataFrame()
        network_df = pl.DataFrame(all_network_events) if all_network_events else pl.DataFrame()
        
        # Store as self.data for Q&A analysis
        self.data = {
            "device_file_events": file_df,
            "device_process_events": process_df,
            "device_network_events": network_df
        }
        
        # Generate Q&A pairs
        qa_df = self.generate_question_answer_pairs()
        
        return {
            "device_file_events": file_df,
            "device_process_events": process_df,
            "device_network_events": network_df
        }, self.victims, current_time, qa_df

    def generate_question_answer_pairs(self) -> pl.DataFrame:
        """Generate detection-focused Q&A pairs for ransomware activity using event data"""
        # Only use malicious data for analysis since schema mismatch prevents concatenation
        malicious_files = self.data["device_file_events"]
        malicious_process = self.data["device_process_events"]
        malicious_network = self.data["device_network_events"]

        questions = []
        answers = []

        # Q1: What file extensions were used for encrypted files?
        questions.append("What file extensions were used for encrypted files?")
        if not malicious_files.is_empty():
            encrypted_exts = malicious_files.select(
                pl.col("FileName").str.split(".").list.last()
            ).unique().to_series().to_list()
            answers.append(", ".join([e for e in encrypted_exts if e is not None]) if encrypted_exts else "No encrypted files detected")
        else:
            answers.append("No encrypted files detected")

        # Q2: What processes were used for the encryption activity?
        questions.append("What processes were used for the encryption activity?")
        enc_procs = malicious_process.select("FileName").unique().to_series().to_list() if "FileName" in malicious_process.columns else []
        answers.append(", ".join([p for p in enc_procs if p is not None]) if enc_procs else "No encryption processes detected")

        # Q3: What directories were targeted by the ransomware?
        questions.append("What directories were targeted by the ransomware?")
        if not malicious_files.is_empty():
            # Extract directory names from file paths
            dirs = set()
            for fname in malicious_files.select("FileName").to_series().to_list():
                if fname is not None:
                    parts = fname.split("\\")
                    if len(parts) > 3:
                        dirs.add(parts[3])
            answers.append(", ".join(sorted(dirs)) if dirs else "No directories detected")
        else:
            answers.append("No directories detected")

        # Q4: What evidence of ransomware is there being used on the network?
        questions.append("What evidence of ransomware is there being used on the network?")
        evidence = []
        if not malicious_network.is_empty():
            if "RemoteIP" in malicious_network.columns:
                c2_domains = malicious_network.select(
                    pl.col("RemoteIP").str.extract(r"https://([^/]+)")
                ).unique().to_series().to_list()
                c2_ports = malicious_network.select("RemotePort").unique().to_series().to_list() if "RemotePort" in malicious_network.columns else []
                if c2_domains:
                    valid_domains = [d for d in c2_domains if d is not None]
                    valid_ports = [str(p) for p in c2_ports if p is not None]
                    if valid_domains and valid_ports:
                        evidence.append(f"C2 communications to {', '.join(valid_domains)} over ports {', '.join(valid_ports)}")
        if not malicious_process.is_empty():
            enc_procs = malicious_process.select("FileName").unique().to_series().to_list() if "FileName" in malicious_process.columns else []
            valid_procs = [p for p in enc_procs if p is not None]
            if valid_procs:
                evidence.append(f"Suspicious processes ({', '.join(valid_procs)}) making outbound network connections")
        answers.append("; ".join(evidence) if evidence else "No network-based evidence detected")

        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False) 