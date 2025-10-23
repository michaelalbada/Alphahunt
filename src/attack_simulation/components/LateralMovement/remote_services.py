import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm
from collections import Counter

from ..utils import (
    generate_identity_info,
    generate_aad_sign_in_events,
    generate_device_info,
    generate_device_events,
    generate_device_file_events,
    generate_device_process_events,
    generate_email_events,
    generate_inbound_network_events,
    generate_outbound_network_events
)

class RemoteServicesAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.attacker = attacker
        self.data = None
        self.used_services = set()  # Track which services were actually used
        self.remote_services = {
            "rdp": {"port": 3389, "process": "mstsc.exe", "protocol": "TCP", "cmdline_pattern": "mstsc.exe /v:{target}"},
            "ssh": {"port": 22, "process": "ssh.exe", "protocol": "TCP", "cmdline_pattern": "ssh.exe {user}@{target}"},
            "vnc": {"port": 5900, "process": "vncviewer.exe", "protocol": "TCP", "cmdline_pattern": "vncviewer.exe {target}:5900"},
            "winrm": {"port": 5985, "process": "winrm.cmd", "protocol": "TCP", "cmdline_pattern": "winrm quickconfig -q"},
            "psexec": {"port": 445, "process": "psexec.exe", "protocol": "TCP", "cmdline_pattern": "psexec.exe \\\\{target} -u {user} -p {password} cmd.exe"}
        }

    def generate_remote_services_attack(self):
        data = {}
        process_events = []
        network_events = []
        signin_events = []
        
        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        compromised_victims = set()
        victim_selected = False

        for victim in tqdm(self.victims.iter_rows(named=True), desc="Generating remote services events"):
            if random.random() < 0.3 or not victim_selected:
                victim_selected = True
                compromised_victims.add(victim["AccountUpn"])

                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                
                target_device = user_devices.sample(n=1)
                target_device = dict(zip(target_device.columns, target_device.row(0)))
                
                service_type = random.choice(list(self.remote_services.keys()))
                service = self.remote_services[service_type]
                self.used_services.add(service_type)  # Track which service was used
                
                connect_time = campaign_time + timedelta(seconds=random.randint(0, 600))
                
                password = self.fake.password()
                cmd_line = service["cmdline_pattern"].format(
                    target=target_device["DeviceName"],
                    user=victim["AccountName"],
                    password=password
                )
                
                process_events.append(
                    generate_device_process_events(
                        identity_row=self.attacker,
                        device_row={"DeviceId": self.fake.uuid4(), "DeviceName": self.attacker.get("DeviceName", self.fake.hostname())},
                        timestamp=connect_time,
                        fake=self.fake,
                        file_name=service["process"],
                        process_command_line=cmd_line
                    )
                )
                
                net_time = connect_time + timedelta(seconds=random.randint(1, 10))
                network_events.append(
                    generate_outbound_network_events(
                        identity_row=self.attacker,
                        device_row={"DeviceId": self.fake.uuid4(), "DeviceName": self.attacker.get("DeviceName", self.fake.hostname()), 
                                  "PublicIP": self.attacker.get("SenderIPv4", self.fake.ipv4())},
                        timestamp=net_time,
                        fake=self.fake,
                        remote_ip=target_device.get("SenderIPv4", self.fake.ipv4()),
                        remote_url=target_device["DeviceName"],
                        remote_port=service["port"]
                    )
                )

                network_events.append(
                    generate_inbound_network_events(
                        identity_row=victim,
                        device_row=target_device,
                        timestamp=net_time + timedelta(seconds=random.randint(1, 5)),
                        fake=self.fake,
                        remote_ip=self.attacker.get("SenderIPv4", self.fake.ipv4()),
                        remote_url=self.attacker.get("DeviceName", self.fake.hostname()),
                        remote_port=random.randint(49152, 65535)
                    )
                )

                auth_time = net_time + timedelta(seconds=random.randint(5, 15))
                signin_events.append(
                    generate_aad_sign_in_events(
                        identity_row=victim,
                        timestamp=auth_time,
                        fake=self.fake,
                        ip_address=self.attacker.get("SenderIPv4", self.fake.ipv4())
                    )
                )
                
                if random.random() < 0.8:
                    activity_time = auth_time + timedelta(seconds=random.randint(10, 60))
                    
                    for i in range(random.randint(2, 5)):
                        cmd_delay = timedelta(seconds=random.randint(30, 120) * i)
                        command = random.choice([
                            "whoami",
                            "net user",
                            "ipconfig /all",
                            "dir C:\\Users",
                            "netstat -ano",
                            "systeminfo",
                            "query user",
                            "tasklist"
                        ])
                        
                        process_events.append(
                            generate_device_process_events(
                                identity_row=victim,
                                device_row=target_device,
                                timestamp=activity_time + cmd_delay,
                                fake=self.fake,
                                file_name="cmd.exe",
                                process_command_line=f"cmd.exe /c {command}"
                            )
                        )

        data["device_process_events"] = (
            pl.DataFrame(process_events).sort("Timestamp") if process_events else pl.DataFrame()
        )
        data["device_network_events"] = (
            pl.DataFrame(network_events).sort("Timestamp") if network_events else pl.DataFrame()
        )
        data["aad_sign_in_events_beta"] = (
            pl.DataFrame(signin_events).sort("Timestamp") if signin_events else pl.DataFrame()
        )
        self.data = data

        last_event_time = None
        all_events = process_events + network_events + signin_events
        if all_events:
            timestamps = [event["Timestamp"] for event in all_events]
            last_event_time = max(timestamps)
            
        compromised_victims = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims)) if compromised_victims else pl.DataFrame()

        return data, compromised_victims, last_event_time

    def generate_question_answer_pairs(self):
        if not self.data:
            return pl.DataFrame({"Question": [], "Answer": []})
            
        all_process_events = pl.concat(
            [self.benign_data.get("device_process_events", pl.DataFrame()), self.data.get("process_events", pl.DataFrame())]
        ) if "device_process_events" in self.benign_data and "process_events" in self.data and len(self.data["process_events"]) > 0 else pl.DataFrame()
        
        all_network_events = pl.concat(
            [self.benign_data.get("device_network_events", pl.DataFrame()), self.data.get("device_network_events", pl.DataFrame())]
        ) if "device_network_events" in self.benign_data and "device_network_events" in self.data and len(self.data["device_network_events"]) > 0 else pl.DataFrame()
        
        all_signin_events = pl.concat(
            [self.benign_data.get("aad_sign_in_events_beta", pl.DataFrame()), self.data.get("aad_sign_in_events_beta", pl.DataFrame())]
        ) if "aad_sign_in_events_beta" in self.benign_data and "aad_sign_in_events_beta" in self.data and len(self.data["aad_sign_in_events_beta"]) > 0 else pl.DataFrame()

        questions = []
        answers = []

        # Q1: Remote services used
        questions.append("Which remote services were used in the attack?")
        if len(all_network_events) > 0:
            service_ports = {
                3389: "RDP",
                22: "SSH", 
                5900: "VNC",
                5985: "WinRM",
                445: "SMB/PsExec"
            }
            used_ports = all_network_events.get_column("RemotePort").unique().to_list()
            used_services = [service_ports[port] for port in used_ports if port in service_ports]
            answers.append(", ".join(used_services) if used_services else "No remote services detected")
        else:
            answers.append("No remote services detected")

        # Q2: Most targeted port number
        questions.append("What was the most commonly targeted port number in the remote services attack?")
        if len(all_network_events) > 0:
            port_counts = all_network_events.group_by("RemotePort").count().sort("count", descending=True)
            if len(port_counts) > 0:
                most_common_port = port_counts.get_column("RemotePort")[0]
                answers.append(str(most_common_port))
            else:
                answers.append("No ports detected")
        else:
            answers.append("No ports detected")

        # Q3: Number of devices targeted
        questions.append("How many unique devices were targeted in the remote services attack?")
        if len(all_network_events) > 0:
            unique_targets = len(all_network_events.get_column("RemoteIP").unique())
            answers.append(str(unique_targets))
        else:
            answers.append("0")

        # Q4: Source IP of the attacker
        questions.append("What IP address was most frequently used as the source for remote service connections?")
        if len(all_network_events) > 0:
            ip_counts = all_network_events.group_by("LocalIP").count().sort("count", descending=True)
            if len(ip_counts) > 0:
                most_common_ip = ip_counts.get_column("LocalIP")[0]
                answers.append(most_common_ip)
            else:
                answers.append("No source IPs detected")
        else:
            answers.append("No source IPs detected")

        # Q5: Most common command executed after connection
        questions.append("What was the most common command executed after establishing a remote connection?")
        if len(all_process_events) > 0 and len(all_network_events) > 0:
            # Get the first connection time
            first_conn = all_network_events.get_column("Timestamp").min()
            if first_conn:
                # Get commands executed after the first connection
                post_conn_events = all_process_events.filter(pl.col("Timestamp") > first_conn)
                if len(post_conn_events) > 0:
                    cmd_lines = post_conn_events.get_column("ProcessCommandLine").to_list()
                    commands = []
                    for cmd in cmd_lines:
                        if cmd and ("/c" in cmd or "/k" in cmd):
                            parts = cmd.split("/c" if "/c" in cmd else "/k", 1)
                            if len(parts) > 1:
                                commands.append(parts[1].strip())
                    if commands:
                        from collections import Counter
                        most_common = Counter(commands).most_common(1)[0][0]
                        answers.append(most_common)
                    else:
                        answers.append("No commands detected")
                else:
                    answers.append("No post-connection commands detected")
            else:
                answers.append("No connection time found")
        else:
            answers.append("No process or network events detected")

        # Q6: Authentication success rate
        questions.append("What percentage of remote access authentication attempts were successful?")
        if len(all_signin_events) > 0:
            successful = len(all_signin_events.filter(pl.col("ErrorCode") == 0))
            total = len(all_signin_events)
            if total > 0:
                success_rate = (successful / total) * 100
                answers.append(f"{success_rate:.1f}%")
            else:
                answers.append("0%")
        else:
            answers.append("No authentication attempts detected")

        # Q7: Number of unique accounts used
        questions.append("How many unique user accounts were used in the remote services attack?")
        if len(all_signin_events) > 0:
            unique_accounts = len(all_signin_events.get_column("AccountUpn").unique())
            answers.append(str(unique_accounts))
        else:
            answers.append("0")

        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
