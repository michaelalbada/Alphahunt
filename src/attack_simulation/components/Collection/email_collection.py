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

class EmailCollectionAttackGenerator:

    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        
        self.data = None
        self.attacker = attacker
        self.compromised_accounts = []
        self.collection_times = {}
    
    def generate_email_collection_attack(self):
        data = {}

        device_process_events = []
        network_events = []
        email_events = []
        
        # Attack start time
        attack_start_time = self.fake.date_time_between(
            start_date=self.last_scan_time, 
            end_date=datetime.today()
        )

        available_victims = self.victims.height
        num_victims = max(1, min(int(available_victims * 1), 5, available_victims))
        num_victims = min(num_victims, available_victims)  # Ensure we do not sample more than available
        selected_victims = self.victims.sample(n=num_victims)
        self.compromised_accounts = selected_victims.to_dicts()
        
        for victim in tqdm(self.compromised_accounts, desc="Generating email collection events"):

            login_time = attack_start_time + timedelta(minutes=random.randint(0, 30))
            
            user_devices = self.benign_data["device_info"].filter(
                pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
            )
            
            if user_devices.height > 0:
                device_info = user_devices.sample(n=1).to_dicts()[0]

                process_time = login_time + timedelta(minutes=random.randint(5, 15))
                
                email_tools = [
                    # PowerShell commands for email access
                    {"name": "powershell.exe", "cmd": "powershell.exe -ExecutionPolicy Bypass -Command \"$Outlook = New-Object -ComObject Outlook.Application; $Namespace = $Outlook.GetNamespace('MAPI'); $Inbox = $Namespace.GetDefaultFolder(6); $Items = $Inbox.Items; foreach($Item in $Items) {$Item.Subject}\""},
                    # IMAP access 
                    {"name": "python.exe", "cmd": "python.exe -c \"import imaplib, email; mail = imaplib.IMAP4_SSL('mail.example.com'); mail.login('user@example.com', 'password'); mail.select('inbox'); status, data = mail.search(None, 'ALL'); for num in data[0].split(): mail.fetch(num, '(RFC822)')\""},
                    # Email exfiltration
                    {"name": "cmd.exe", "cmd": "cmd.exe /c powershell.exe -Command \"Get-ChildItem -Path C:\\Users\\user\\Documents\\emails -Recurse | Compress-Archive -DestinationPath C:\\Users\\user\\Documents\\emails.zip\""}
                ]
                
                selected_tool = random.choice(email_tools)
                process_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=device_info,
                    timestamp=process_time,
                    fake=self.fake,
                    file_name=selected_tool["name"],
                    process_command_line=selected_tool["cmd"]
                )
                device_process_events.append(process_event)
                
                exfil_time = process_time + timedelta(minutes=random.randint(2, 10))
                self.collection_times[victim["AccountUpn"]] = exfil_time

                for _ in range(random.randint(5, 15)):
                    email_forward_time = exfil_time + timedelta(seconds=random.randint(30, 300))
                    
                    # Email forwarding event
                    email_event = generate_email_events(
                        identity_row_sender=victim,
                        identity_row_recipient=self.attacker,
                        timestamp=email_forward_time,
                        in_network=False,
                        fake=self.fake,
                        know_sender=True,
                        subject=f"FWD: {self.fake.sentence()}"
                    )
                    email_events.append(email_event)
        
        if device_process_events:
            data["device_process_events"] = pl.DataFrame(device_process_events).sort("Timestamp")
            
        if network_events:
            data["device_network_events"] = pl.DataFrame(network_events).sort("Timestamp")
            
        if email_events:
            data["email_events"] = pl.DataFrame(email_events).sort("Timestamp")
            
        self.data = data
        
        last_event_time = datetime.now()
        if network_events:
            last_event_time = max(event["Timestamp"] for event in network_events)

        return data, selected_victims, last_event_time
    
    def generate_question_answer_pairs(self):
        questions = []
        answers = []
        
        # Initial detection questions
        Q1 = "Is there evidence of email collection or theft in the environment?"
        Q1_answer = (
            "Yes" if self.data.get("email_events", pl.DataFrame()).height > 0 else "No"
        )
        questions.append(Q1)
        answers.append(Q1_answer)
        
        # Identify compromised accounts
        Q2 = "Which accounts appear to have been compromised for email collection?"
        Q2_answer = [account["AccountUpn"] for account in self.compromised_accounts]
        questions.append(Q2)
        answers.append(Q2_answer)
        
        # Determine technique details
        Q3 = "What methods were used to collect the email data?"
        technique_indicators = []
        
        if "device_process_events" in self.data:
            processes = self.data["device_process_events"]
            if processes.filter(pl.col("ProcessCommandLine").str.contains("Outlook")).height > 0:
                technique_indicators.append("PowerShell commands to access Outlook")
            if processes.filter(pl.col("ProcessCommandLine").str.contains("imaplib")).height > 0:
                technique_indicators.append("Python IMAP library for email access")
            if processes.filter(pl.col("ProcessCommandLine").str.contains("Compress-Archive")).height > 0:
                technique_indicators.append("PowerShell commands to compress email data")
                
        Q3_answer = technique_indicators if technique_indicators else "Unknown or encrypted methods"
        questions.append(Q3)
        answers.append(Q3_answer)
        
        # Identify potential exfiltration
        Q4 = "Is there evidence of data exfiltration after email collection?"
        Q4_answer = (
            "Yes" if "outbound_network_events" in self.data else "No"
        )
        questions.append(Q4)
        answers.append(Q4_answer)
        
        # Timeline analysis
        Q6 = "What is the timeline of the email collection attack?"
        timeline = {}
        for account in self.compromised_accounts:
            upn = account["AccountUpn"]
            if upn in self.collection_times:
                timeline[upn] = self.collection_times[upn].strftime("%Y-%m-%d %H:%M:%S")
        
        Q6_answer = timeline
        questions.append(Q6)
        answers.append(Q6_answer)
        
        # Impact assessment
        Q7 = "How many emails were potentially accessed or exfiltrated?"
        if "email_events" in self.data:
            email_count = self.data["email_events"].height
            Q7_answer = f"Approximately {email_count} emails were potentially exfiltrated"
        else:
            Q7_answer = "Unable to determine the exact number"
        questions.append(Q7)
        answers.append(Q7_answer)
        
        # Mitigation recommendations
        Q8 = "What immediate actions should be taken to respond to this email collection incident?"
        Q8_answer = [
            "Reset passwords for all affected accounts",
            "Enable MFA for affected accounts if not already enabled",
            "Block identified malicious IP addresses in firewalls",
            "Review email forwarding rules for affected accounts",
            "Analyze email gateway logs for additional exfiltration evidence",
            "Consider implementing data loss prevention (DLP) policies"
        ]
        questions.append(Q8)
        answers.append(Q8_answer)
        
        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df