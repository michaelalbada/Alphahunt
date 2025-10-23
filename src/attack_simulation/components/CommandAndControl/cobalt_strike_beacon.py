import random
import datetime
from faker import Faker
import polars as pl
from typing import Dict, List, Tuple, Any
from src.attack_simulation.components.utils import (
    generate_device_network_events,
    generate_device_process_events,
    generate_device_events
)

class CobaltStrikeBeaconGenerator:
    """Generator for Cobalt Strike Beacon C2 traffic and events (T1071)"""
    
    def __init__(self, benign_data: Dict[str, pl.DataFrame], victims: List[Dict[str, Any]],
                 attacker: Dict[str, str], last_scan_time: datetime.datetime, 
                 network_patterns: Dict[str, List[str]], beacon_config: Dict[str, Any]):
        """
        Initialize the Cobalt Strike beacon generator
        
        Args:
            benign_data: Dictionary of benign data DataFrames
            victims: List of victim information
            attacker: Dictionary containing attacker information
            last_scan_time: Last scan time for event generation
            network_patterns: Dictionary containing domains, prefixes, uri_patterns, and user_agents
            beacon_config: Dictionary containing intervals, jitter_percentage, ports, and http_methods
        """
        self.benign_data = benign_data
        self.victims = victims
        self.attacker = attacker
        self.last_event_time = last_scan_time
        self.fake = Faker()
        
        # Network patterns from config
        self.uri_patterns = network_patterns.get('uri_patterns', [])
        self.user_agents = network_patterns.get('user_agents', [])
        
        # Beacon configuration from config
        self.beacon_intervals = beacon_config.get('intervals', [60, 120, 180, 300])
        self.jitter_percentage = beacon_config.get('jitter_percentage', 20)
        self.c2_ports = beacon_config.get('ports', [80, 443])
        self.http_methods = beacon_config.get('http_methods', ['GET', 'POST'])
        
        # Validate required configuration
        if not all([self.uri_patterns, self.user_agents, self.beacon_intervals, 
                   self.c2_ports, self.http_methods]):
            raise ValueError("Missing required C2 configuration parameters")

    def generate_beacon_traffic(self, victim: Dict[str, Any], start_time: datetime.datetime) -> List[Dict[str, Any]]:
        """Generate Cobalt Strike beacon network traffic events (XDR-compliant)"""
        events = []
        current_time = start_time
        base_interval = random.choice(self.beacon_intervals)
        
        # Calculate jitter based on configured percentage
        jitter_factor = 1 + (random.uniform(-self.jitter_percentage, self.jitter_percentage) / 100)
        beacon_interval = int(base_interval * jitter_factor)
        c2_port = random.choice(self.c2_ports)
        
        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events
            
        device_info = user_devices.sample(n=1).to_dicts()[0]
        
        # Generate multiple beacon events
        for _ in range(random.randint(5, 15)):
            event = generate_device_network_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=current_time,
                fake=self.fake,
                process_name="svchost.exe",
                destination_ip=self.attacker["ExternalServerIP"],
                destination_port=c2_port,
                protocol="TCP",
                url=f"https://{self.attacker['ExternalServerName']}{random.choice(self.uri_patterns)}",
                user_agent=random.choice(self.user_agents),
                http_headers=None
            )
            events.append(event)
            current_time += datetime.timedelta(seconds=beacon_interval)
            
        return events

    def generate_process_events(self, victim: Dict[str, Any], start_time: datetime.datetime) -> List[Dict[str, Any]]:
        """Generate process events associated with Cobalt Strike beacon (XDR-compliant)"""
        events = []

        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events

        device_info = user_devices.sample(n=1).to_dicts()[0]

        # Initial process creation
        event = generate_device_process_events(
            identity_row=victim,
            device_row=device_info,
            timestamp=start_time,
            fake=self.fake,
            file_name="svchost.exe",
            process_command_line="C:\\Windows\\System32\\svchost.exe -k netsvcs"
        )
        events.append(event)

        return events

    def generate_dns_events(self, victim: Dict[str, Any], start_time: datetime.datetime) -> List[Dict[str, Any]]:
        """Generate DNS query events for C2 communication (XDR-compliant)"""
        events = []

        # Get device info for the victim
        user_devices = self.benign_data["device_info"].filter(
            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
        )
        if user_devices.height == 0:
            return events

        device_info = user_devices.sample(n=1).to_dicts()[0]

        # Generate a single DNS query event using generate_device_events with DNS-specific parameters
        event = generate_device_events(
            identity_row=victim,
            device_row=device_info,
            timestamp=start_time,
            fake=self.fake,
            action_type="DnsQuery",
            remote_url=self.attacker["ExternalServerName"],
            remote_ip=self.attacker["ExternalServerIP"],
            process_name="svchost.exe"
        )
        events.append(event)
        return events

    def generate_cobalt_strike_attack(self) -> Tuple[Dict[str, pl.DataFrame], List[Dict[str, Any]], datetime.datetime]:
        """Generate all events related to Cobalt Strike beacon activity"""
        all_network_events = []
        all_process_events = []
        all_dns_events = []
        current_time = self.last_event_time
        
        victims_list = self.victims.to_dicts()
        for victim in victims_list:
            # Generate events for each victim
            network_events = self.generate_beacon_traffic(victim, current_time)
            process_events = self.generate_process_events(victim, current_time)
            dns_events = self.generate_dns_events(victim, current_time)
            
            all_network_events.extend(network_events)
            all_process_events.extend(process_events)
            all_dns_events.extend(dns_events)
            
            # Update the last event time
            event_times = []
            for e in network_events + process_events + dns_events:
                ts = e["Timestamp"]
                if isinstance(ts, str):
                    try:
                        ts = datetime.datetime.fromisoformat(ts)
                    except ValueError:
                        continue
                if isinstance(ts, datetime.datetime):
                    event_times.append(ts)

            if event_times:
                current_time = max(event_times)
        
        # Convert to polars DataFrames
        network_df = pl.DataFrame(all_network_events)
        process_df = pl.DataFrame(all_process_events)
        dns_df = pl.DataFrame(all_dns_events)
        
        # Store as self.data for Q&A analysis
        self.data = {
            "device_network_events": network_df,
            "device_process_events": process_df,
            "device_events": dns_df
        }
        return self.data, self.victims, current_time

    def generate_question_answer_pairs(self) -> pl.DataFrame:
        """Generate detection-focused Q&A pairs for Cobalt Strike beacon activity using event data, with original question wording."""
        # Get all network events that match our C2 patterns
        malicious_network = self.data["device_network_events"].filter(
            pl.col("RemoteUrl").str.contains("|".join(self.uri_patterns))
        )
        malicious_process = self.data["device_process_events"]

        questions = [
            "What is the most common call pattern that we are seeing with the command and control server?",
            "What are common beacon intervals observed in the C2 traffic?",
            "What process name was commonly used for the Cobalt Strike beacon?",
            "What process name is showing suspicious patterns that appear to be interactions with a command and control server?"
        ]
        answers = []

        # Q1: Most common call pattern (method, domain, port, interval)
        if not malicious_network.is_empty():
            # Find the most common (RemoteUrl, RemotePort) tuple
            call_patterns = malicious_network.group_by(["RemoteUrl", "RemotePort"]).count().sort("count", descending=True)
            if call_patterns.height > 0:
                row = call_patterns.row(0)
                url, port = row[0], row[1]
                # Verify the port exists in the actual events
                port_counts = malicious_network.group_by("RemotePort").count().sort("count", descending=True)
                most_common_port = port_counts["RemotePort"][0] if port_counts.height > 0 else port
                answer = f"The most common call pattern is requests to {url} over port {most_common_port}."
            else:
                answer = "No call pattern detected."
        else:
            answer = "No C2 network events detected."
        answers.append(answer)

        # Q2: Common beacon intervals
        if not malicious_network.is_empty() and "Timestamp" in malicious_network.columns:
            timestamps = malicious_network.sort("Timestamp").select("Timestamp").to_series().to_list()
            intervals = []
            for i in range(1, len(timestamps)):
                try:
                    t1 = datetime.datetime.strptime(timestamps[i-1], "%Y-%m-%d %H:%M:%S.%f")
                    t2 = datetime.datetime.strptime(timestamps[i], "%Y-%m-%d %H:%M:%S.%f")
                    intervals.append(int((t2 - t1).total_seconds()))
                except Exception:
                    continue
            if intervals:
                from collections import Counter
                most_common = Counter(intervals).most_common(3)
                interval_str = ", ".join(f"{val} sec (x{cnt})" for val, cnt in most_common)
                answer = f"Common beacon intervals: {interval_str}"
            else:
                answer = "No regular beacon intervals detected."
        else:
            answer = "No C2 network events detected."
        answers.append(answer)

        # Q3: Most common process name for the beacon
        if not malicious_process.is_empty():
            process_names = malicious_process.get_column("FileName").to_list()
            from collections import Counter
            if process_names:
                most_common = Counter(process_names).most_common(1)[0][0]
                answer = f"{most_common} was used as the process name for the beacon."
            else:
                answer = "No process events detected."
        else:
            answer = "No process events detected."
        answers.append(answer)

        # Q4: Process name showing suspicious C2 patterns
        if not malicious_network.is_empty():
            process_names = malicious_network.get_column("InitiatingProcessFileName").to_list()
            from collections import Counter
            if process_names:
                most_common = Counter(process_names).most_common(1)[0][0]
                answer = f"{most_common} is showing suspicious beaconing patterns with regular intervals to an external C2 server."
            else:
                answer = "No process names found in network events."
        else:
            answer = "No C2 network events detected."
        answers.append(answer)

        return pl.DataFrame({
            "Question": questions,
            "Answer": answers
        }) 