from ..utils import generate_device_network_events
import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm

class NetworkActivityGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time, network_patterns=None, beacon_config=None):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.attacker = attacker
        self.data = None
        self.beacon_config = beacon_config or {}

        if not network_patterns:
            raise ValueError("Network patterns must be provided from the attack chain configuration")

        # Use network patterns from the chain config
        self.c2_domains = network_patterns['domains']
        self.uri_patterns = network_patterns['uri_patterns']
        self.user_agents = network_patterns['user_agents']

        # Common legitimate HTTP headers
        self.http_headers = network_patterns.get('http_headers', {
            "Accept": ["text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"],
            "Accept-Language": ["en-US,en;q=0.5"],
            "Accept-Encoding": ["gzip, deflate, br"],
            "Connection": ["keep-alive"],
            "Cache-Control": ["max-age=0"],
            "Upgrade-Insecure-Requests": ["1"],
            "DNT": ["1"]
        })
        self.protocols = network_patterns.get('protocols', ["TCP"])
        self.c2_probability = network_patterns.get('c2_probability', 0.3)
        self.beacons_per_victim_min = network_patterns.get('beacons_per_victim_min', 3)
        self.beacons_per_victim_max = network_patterns.get('beacons_per_victim_max', 7)

        # Common ports used for C2
        self.c2_ports = network_patterns.get('ports', [80, 443, 8080, 8443, 4443, 4444])

        # Common processes that could be used for C2
        self.c2_processes = network_patterns.get('c2_processes', [
            "svchost.exe",
            "beacon.exe",
            "csrss.exe",
            "dllhost.exe",
            "explorer.exe",
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "opera.exe"
        ])

    def generate_network_activity(self):
        network_events = []
        compromised_devices = set()
        
        campaign_time = self.fake.date_time_between(start_date=self.last_scan_time, end_date=datetime.today())
        
        for victim in tqdm(self.victims.iter_rows(named=True), desc="Generating network activity events"):
            if random.random() < self.c2_probability:
                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                if not user_devices.height:
                    continue
                    
                user_device = user_devices.sample(n=1)
                user_device = dict(zip(user_device.columns, user_device.row(0)))
                compromised_devices.add(user_device["DeviceId"])

                # Generate initial beacon
                beacon_time = campaign_time
                for _ in range(random.randint(self.beacons_per_victim_min, self.beacons_per_victim_max)):
                    domain = random.choice(self.c2_domains)
                    uri = random.choice(self.uri_patterns)
                    port = random.choice(self.c2_ports)
                    process = random.choice(self.c2_processes)
                    user_agent = random.choice(self.user_agents)
                    protocol = random.choice(self.protocols)
                    
                    # Add randomization to beacon intervals using config if available
                    intervals = self.beacon_config.get('intervals', [30, 60, 120, 180, 300, 600])
                    beacon_interval = random.choice(intervals)
                    beacon_time = beacon_time + timedelta(seconds=beacon_interval)
                    
                    network_event = generate_device_network_events(
                        identity_row=self.attacker,
                        device_row=user_device,
                        timestamp=beacon_time,
                        fake=self.fake,
                        process_name=process,
                        destination_ip=self.fake.ipv4(),
                        destination_port=port,
                        protocol=protocol,
                        url=f"https://{domain}{uri}",
                        user_agent=user_agent,
                        http_headers=self.http_headers
                    )
                    network_events.append(network_event)

        self.data = {
            "network_events": pl.DataFrame(network_events).sort("Timestamp") if network_events else pl.DataFrame()
        }
        compromised_devices = pl.DataFrame(list(compromised_devices), schema=["DeviceId"])
        last_event_time = self.data["network_events"]["Timestamp"].max() if not self.data["network_events"].is_empty() else None
        qa = self.generate_question_answer_pairs()

        return self.data, compromised_devices, last_event_time, qa

    def generate_question_answer_pairs(self):
        malicious_network = self.data["network_events"]
        all_network_events = pl.concat([self.benign_data["device_network_events"], malicious_network])
        
        questions = []
        answers = []
        
        # Question about C2 domains
        questions.append("What domains were used for C2 communication?")
        domains = malicious_network.select(pl.col("Url").str.extract(r"https://([^/]+)")).unique().to_series().to_list()
        answers.append(", ".join(domains) if domains else "No C2 domains detected")
        
        # Question about URI patterns
        questions.append("What URI patterns were used in C2 communication?")
        uris = malicious_network.select(pl.col("Url").str.extract(r"https://[^/]+(/.*)")).unique().to_series().to_list()
        answers.append(", ".join(uris) if uris else "No C2 URIs detected")
        
        # Question about ports
        questions.append("What ports were used for C2 communication?")
        ports = malicious_network.select("DestinationPort").unique().to_series().to_list()
        answers.append(", ".join(map(str, ports)) if ports else "No C2 ports detected")
        
        # Question about processes
        questions.append("What processes were involved in C2 communication?")
        processes = malicious_network.select("ProcessName").unique().to_series().to_list()
        answers.append(", ".join(processes) if processes else "No C2 processes detected")
        
        # Question about beacon intervals
        questions.append("What were the beacon intervals observed?")
        timestamps = malicious_network.select("Timestamp").to_series().to_list()
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        answers.append(f"The beacon intervals observed were {', '.join(map(str, sorted(set(intervals))))} seconds" if intervals else "No beacon intervals detected")
        
        # Question about user agents
        questions.append("What user agents were used in C2 communication?")
        user_agents = malicious_network.select("UserAgent").unique().to_series().to_list()
        answers.append(", ".join(user_agents) if user_agents else "No user agents detected")
        
        # Question about HTTP headers
        questions.append("What HTTP headers were used in C2 communication?")
        headers = malicious_network.select("HttpHeaders").unique().to_series().to_list()
        answers.append(", ".join(headers) if headers else "No HTTP headers detected")
        
        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False) 