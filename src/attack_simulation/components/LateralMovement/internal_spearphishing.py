import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm
from collections import Counter
import re

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

class InternalSpearphishingAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.attacker = attacker
        self.data = None
        self.malicious_subjects = [
            "Urgent: Security Alert - Action Required",
            "Password Reset Required Immediately",
            "Important: Your Account Access Will Be Suspended",
            "IT Department: Critical System Update",
            "Payroll Information Update Required",
            "Company Policy Update - Acknowledge Now",
            "Security Check: Unusual Login Activity",
            "Internal Memo: Confidential Information",
            "HR Department: Important Benefits Update",
            "Please Confirm Your Login Credentials"
        ]
        self.malicious_attachments = [
            "Security_Update.docx",
            "Payroll_Information.xlsx",
            "Company_Policy.pdf",
            "System_Update.exe",
            "Benefits_Form.xlsm",
            "Account_Reset.html",
            "IT_Security_Memo.pptx",
            "Login_Portal.html",
            "Employee_Survey.zip",
            "VPN_Config.cmd"
        ]
        self.phishing_domains = [
            "securityalert-company.com",
            "internal-companyportal.net",
            "company-helpdesk.org",
            "secure-login-portal.com",
            "it-support-team.net",
            "employee-benefits-update.com",
            "payroll-system-update.org",
            "account-verification-portal.net",
            "corporate-security-alert.com",
            "system-update-required.net"
        ]

    def generate_internal_spearphishing_attack(self):
        data = {}
        email_events = []
        process_events = []
        device_file_events = []
        network_events = []
        
        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        victim_selected = False
        compromised_accounts = []

        for compromised_account in tqdm(self.victims.iter_rows(named=True), desc="Generating spearphishing emails"):
            # Combine victims with randomly selected users from benign data to increase target pool
            potential_victims = list(self.victims.iter_rows(named=True))
            
            # Select random users from benign_data identity_info as additional potential victims
            if "identity_info" in self.benign_data and self.benign_data["identity_info"].height > 0:
                benign_users = list(self.benign_data["identity_info"].sample(n=min(5, self.benign_data["identity_info"].height)).iter_rows(named=True))
                potential_victims.extend(benign_users)

            random.shuffle(potential_victims)  # Mix the victims for more natural targeting

            for victim in potential_victims:
                if victim["AccountUpn"] == compromised_account["AccountUpn"][0]:
                    continue
                    
                if random.random() < 0.8 or not victim_selected:
                    victim_selected = True
                    

                    email_time = campaign_time + timedelta(minutes=random.randint(0, 120))
                    subject = random.choice(self.malicious_subjects)
                    attachment = random.choice(self.malicious_attachments) if random.random() < 0.7 else None
                    
                    email_event = generate_email_events(
                        identity_row_sender=compromised_account,
                        identity_row_recipient=victim,
                        timestamp=email_time,
                        in_network=True,
                        fake=self.fake,
                        know_sender=True,
                        subject=subject
                    )
                    
                    if attachment:
                        email_event["AttachmentCount"] = 1
                    
                    email_events.append(email_event)
                    
                    # Determine if victim opens/clicks the email (80% chance)
                    if random.random() < 0.8:
                        open_time = email_time + timedelta(minutes=random.randint(5, 60))
                        
                        user_devices = self.benign_data["device_info"].filter(
                            pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                        )
                        
                        if user_devices.height > 0:
                            victim_device = user_devices.sample(n=1)
                            victim_device_dict = dict(zip(victim_device.columns, victim_device.row(0)))
                            
                            email_client = random.choice(["outlook.exe", "chrome.exe", "msedge.exe"])
                            process_events.append(
                                generate_device_process_events(
                                    identity_row=victim,
                                    device_row=victim_device_dict,
                                    timestamp=open_time,
                                    fake=self.fake,
                                    file_name=email_client,
                                    process_command_line=f"{email_client} {subject}"
                                )
                            )
                            
                            # If there's an attachment, generate file events for download
                            if attachment:
                                download_time = open_time + timedelta(minutes=random.randint(1, 5))
                                device_file_events.append(
                                    generate_device_file_events(
                                        identity_row=victim,
                                        device_row=victim_device_dict,
                                        timestamp=download_time,
                                        fake=self.fake
                                    )
                                )
                                
                                # Generate process events for opening the attachment
                                open_attachment_time = download_time + timedelta(seconds=random.randint(10, 60))
                                attachment_process = "winword.exe" if attachment.endswith(".docx") else \
                                                     "excel.exe" if attachment.endswith((".xlsx", ".xlsm")) else \
                                                     "AcroRd32.exe" if attachment.endswith(".pdf") else \
                                                     "powerpnt.exe" if attachment.endswith(".pptx") else \
                                                     "cmd.exe"
                                
                                process_events.append(
                                    generate_device_process_events(
                                        identity_row=victim,
                                        device_row=victim_device_dict,
                                        timestamp=open_attachment_time,
                                        fake=self.fake,
                                        file_name=attachment_process,
                                        process_command_line=f"{attachment_process} C:\\Users\\{victim['AccountName']}\\Downloads\\{attachment}"
                                    )
                                )
                            
                            # Generate network connection to phishing domain (if clicked)
                            if random.random() < 0.7:
                                click_time = open_time + timedelta(minutes=random.randint(1, 10))
                                phishing_domain = random.choice(self.phishing_domains)
                                
                                network_events.append(
                                    generate_outbound_network_events(
                                        identity_row=victim,
                                        device_row={"DeviceId": victim_device_dict["DeviceId"], 
                                                  "DeviceName": victim_device_dict["DeviceName"],
                                                  "PublicIP": victim_device_dict.get("PublicIP", self.fake.ipv4())},
                                        timestamp=click_time,
                                        fake=self.fake,
                                        remote_ip=self.fake.ipv4(),
                                        remote_url=phishing_domain,
                                        remote_port=443
                                    )
                                )
                                    
                        compromised_accounts.append(victim)

        data["email_events"] = (
            pl.DataFrame(email_events).sort("Timestamp") if email_events else pl.DataFrame()
        )
        data["device_process_events"] = (
            pl.DataFrame(process_events).sort("Timestamp") if process_events else pl.DataFrame()
        )
        data["device_file_events"] = (
            pl.DataFrame(device_file_events).sort("Timestamp") if device_file_events else pl.DataFrame()
        )
        data["device_network_events"] = (
            pl.DataFrame(network_events).sort("Timestamp") if network_events else pl.DataFrame()
        )
        self.data = data

        last_event_time = None
        all_events = email_events + process_events + device_file_events + network_events
        if all_events:
            timestamps = [event["Timestamp"] for event in all_events]
            last_event_time = max(timestamps)
            
        compromised_upns = [acc["AccountUpn"] for acc in compromised_accounts]
        compromised_victims_df = self.victims.filter(pl.col("AccountUpn").is_in(compromised_upns)) if compromised_upns else pl.DataFrame()

        return data, compromised_victims_df, last_event_time

    def generate_question_answer_pairs(self):
        if not self.data:
            return pl.DataFrame({"Question": [], "Answer": []})
            
        all_email_events = pl.concat(
            [self.benign_data.get("email_events", pl.DataFrame()), self.data.get("email_events", pl.DataFrame())]
        ) if "email_events" in self.benign_data and "email_events" in self.data and self.data["email_events"].height > 0 else pl.DataFrame()
        
        all_process_events = pl.concat(
            [self.benign_data.get("device_process_events", pl.DataFrame()), self.data.get("device_process_events", pl.DataFrame())]
        ) if "device_process_events" in self.benign_data and "device_process_events" in self.data and self.data["device_process_events"].height > 0 else pl.DataFrame()
        
        all_network_events = pl.concat(
            [self.benign_data.get("device_network_events", pl.DataFrame()), self.data.get("device_network_events", pl.DataFrame())]
        ) if "device_network_events" in self.benign_data and "device_network_events" in self.data and self.data["device_network_events"].height > 0 else pl.DataFrame()

        questions = []
        answers = []

        # Q1: Initial detection - suspicious subject lines
        questions.append("What suspicious email subject line appears most frequently in our mail logs that could indicate an internal spearphishing campaign?")
        if all_email_events.height > 0 and "Subject" in all_email_events.columns:
            # Find subject lines that match our known malicious patterns
            suspicious_emails = all_email_events.filter(
            pl.col("Subject").str.contains("Urgent|Alert|Required|Password|Suspended|Update|Confidential|Confirm|Security|Credentials")
            )
            
            # Count occurrences of each suspicious subject
            if suspicious_emails.height > 0:
                subject_counts = suspicious_emails.group_by("Subject").count().sort("count", descending=True)
                Q1_answer = subject_counts.select("Subject").row(0)[0] if subject_counts.height > 0 else "No suspicious subject lines detected"
            
            # Add context that a SOC analyst would find helpful
                count = subject_counts.select("count").row(0)[0] if subject_counts.height > 0 else 0
                Q1_answer = f"{Q1_answer} (appeared {count} times, contains suspicious keywords like 'urgent' or 'required')"
            else:
                Q1_answer = "No suspicious subject lines detected based on common phishing keywords"
        else:
            Q1_answer = "No email data available for analysis"
        answers.append(Q1_answer)

        # Q2: Identifying compromised sender accounts
        questions.append("How many internal accounts appear to be compromised and are being used to send these suspicious emails?")
        if all_email_events.height > 0:
            phishing_emails = all_email_events.filter(
                pl.col("Subject").is_in(self.malicious_subjects)
            )
            Q2_answer = phishing_emails.select(pl.col("SenderFromAddress").n_unique()).item() if phishing_emails.height > 0 else 0
        else:
            Q2_answer = 0
        answers.append(Q2_answer)

        # Q3: Analysis of malicious payloads
        questions.append("What file attachment is most commonly used as the malicious payload in this campaign?")
        if all_email_events.height > 0 and "AttachmentNames" in all_email_events.columns:
            attachment_counts = Counter()
            for row in all_email_events.filter(pl.col("AttachmentCount") > 0).select("AttachmentNames").to_series():
                if row and isinstance(row, str):
                    attachment_counts[row] += 1
            
            Q3_answer = attachment_counts.most_common(1)[0][0] if attachment_counts else "No malicious attachments detected"
        else:
            Q3_answer = "No attachment data available for analysis"
        answers.append(Q3_answer)

        # Q4: Impact assessment - compromised users
        questions.append("How many users have potentially been compromised based on endpoint process execution evidence?")
        if all_process_events.height > 0:
            # Look for process events that indicate opening attachments or clicking links
            interacting_users = set()
            
            for idx, proc_event in enumerate(all_process_events.iter_rows(named=True)):
                if any(app in proc_event.get("FileName", "") for app in ["winword.exe", "excel.exe", "AcroRd32.exe", "powerpnt.exe"]):
                    if "InitiatingProcessAccountUpn" in proc_event:
                        interacting_users.add(proc_event["InitiatingProcessAccountUpn"])
            
            Q4_answer = len(interacting_users)
        else:
            Q4_answer = 0
        answers.append(Q4_answer)

        # Q5: C2 infrastructure identification
        questions.append("What suspicious domain is receiving the most traffic following user interaction with phishing content?")
        if all_network_events.height > 0 and "RemoteUrl" in all_network_events.columns:
            phishing_domains = all_network_events.filter(
                pl.col("RemoteUrl").is_in(self.phishing_domains)
            ).group_by("RemoteUrl").count().sort("count", descending=True)
            
            Q5_answer = phishing_domains.select("RemoteUrl").row(0)[0] if phishing_domains.height > 0 else "No suspicious domains detected"
        else:
            Q5_answer = "No network data available for analysis"
        answers.append(Q5_answer)

        # Q6: Effectiveness of the attack
        questions.append("What is the success rate of this campaign (percentage of targeted users who engaged with malicious content)?")
        if all_email_events.height > 0 and all_network_events.height > 0:
            total_recipients = all_email_events.filter(
                pl.col("Subject").is_in(self.malicious_subjects)
            ).select(pl.col("RecipientEmailAddress").n_unique()).item()
            
            clickers = set()
            for network_event in all_network_events.filter(
                pl.col("RemoteUrl").is_in(self.phishing_domains)
            ).iter_rows(named=True):
                if "InitiatingProcessAccountUpn" in network_event:
                    clickers.add(network_event["InitiatingProcessAccountUpn"])
            
            Q6_answer = f"{(len(clickers) / total_recipients * 100):.1f}%" if total_recipients > 0 else "Unable to determine"
        else:
            Q6_answer = "Insufficient data for analysis"
        answers.append(Q6_answer)

        # Q7: User behavior analysis
        questions.append("What is the average response time (in minutes) between email delivery and user interaction with malicious content?")
        if all_email_events.height > 0 and all_process_events.height > 0:
            time_gaps = []
            
            for email in all_email_events.filter(pl.col("Subject").is_in(self.malicious_subjects)).iter_rows(named=True):
                recipient = email.get("RecipientEmailAddress")
                email_time = email.get("Timestamp")
                
                # Find corresponding process events that might indicate interaction
                for proc in all_process_events.iter_rows(named=True):
                    if proc.get("InitiatingProcessAccountUpn") == recipient and proc.get("Timestamp") > email_time:
                        time_gap = (proc.get("Timestamp") - email_time).total_seconds() / 60  # Convert to minutes
                        time_gaps.append(time_gap)
                        break
            
            Q7_answer = f"{sum(time_gaps) / len(time_gaps):.1f} minutes" if time_gaps else "Unable to determine"
        else:
            Q7_answer = "Insufficient data for analysis"
        answers.append(Q7_answer)


        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)