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

class PhishingAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims

        self.data = None
        self.phishing_sender = attacker 
        self.phishing_url = self.fake.url()

    def generate_phishing_attack(self):  
        data = {}
        phishing_emails = []
        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        email_subject = self.fake.sentence()

        for victim in tqdm(self.victims.to_dicts(), desc="Generating phishing emails for victims"):
            event_time = campaign_time + timedelta(seconds=random.randint(0, 600))
            email_event = generate_email_events(
                identity_row_sender=self.phishing_sender,
                identity_row_recipient=victim,
                timestamp=event_time,
                in_network=False,
                fake=self.fake,
                know_sender=True,
                subject=email_subject,
            )
            phishing_emails.append(email_event)

        df = pl.DataFrame(phishing_emails).sort("Timestamp")
        data["email_events"] = df

        victim_accounts = self.victims["AccountObjectId"].to_list()
        num_clicked = max(1, int(len(victim_accounts) * 0.3))
        clicked_victims = random.sample(victim_accounts, num_clicked)

        network_events = []
        
        for victim_id in clicked_victims:
            victim_row = self.victims.filter(pl.col("AccountObjectId") == victim_id).to_dicts()[0]

            user_devices = self.benign_data["device_info"].filter(
                pl.col("LoggedOnUsers").str.contains(victim_row["AccountUpn"])
            )
            device_info = user_devices.sample(n=1).to_dicts()[0]

            click_time = campaign_time + timedelta(minutes=random.randint(1, 60))
            
            # Generate outbound network events for the malicious URL click
            network_event = generate_outbound_network_events(
                identity_row=victim_row,
                device_row=device_info,
                timestamp=click_time + timedelta(seconds=random.randint(5, 30)),
                fake=self.fake,
                remote_ip=self.phishing_sender['PhishingIP'],
                remote_url=self.phishing_sender["PhishingURL"],
                remote_port=random.randint(1, 65535)
            )
            network_events.append(network_event)

        data["device_network_events"] = pl.DataFrame(network_events).sort("Timestamp")
        self.data = data

        last_event_time = data["device_network_events"]["Timestamp"].max()
        clicked_victims_df = self.victims.filter(pl.col("AccountObjectId").is_in(clicked_victims))

        return data, clicked_victims_df, last_event_time

    def generate_question_answer_pairs(self):
        # Combine benign and phishing-related events for analysis
        all_email_events = pl.concat([self.benign_data.get("email_events", pl.DataFrame()), self.data.get("email_events", pl.DataFrame())])
        all_network_events = pl.concat([self.benign_data.get("outbound_network_events", pl.DataFrame()), self.data.get("device_network_events", pl.DataFrame())])
        
        questions = []
        answers = []
        
        # Initial detection questions
        Q1 = "Is there evidence of unusual email activity in the environment?"
        Q1_answer = (
            "Yes" if all_email_events.filter(
                pl.col("SenderMailFromAddress") == self.phishing_sender["AccountUpn"]
            ).height > 0 else "No"
        )
        questions.append(Q1)
        answers.append(Q1_answer)
        
        # Identify the threat actor/sender
        Q2 = "Who is the potential phishing email sender (threat actor)?"
        Q2_answer = self.phishing_sender["AccountUpn"]
        questions.append(Q2)
        answers.append(Q2_answer)
        
        # Understand attack characteristics
        Q3 = "What was the subject line used in the suspected phishing campaign?"
        Q3_answer = (
            all_email_events
            .filter(pl.col("SenderMailFromAddress") == self.phishing_sender["AccountUpn"])
            .select("Subject")
            .unique()
            .item(0, 0)
        )
        questions.append(Q3)
        answers.append(Q3_answer)
        
        # Assess attack scope
        Q4 = "How many users were targeted in this phishing campaign?"
        Q4_answer = (
            all_email_events
            .filter(pl.col("SenderMailFromAddress") == self.phishing_sender["AccountUpn"])
            .select("RecipientEmailAddress")
            .unique()
            .height
        )
        questions.append(Q4)
        answers.append(Q4_answer)
        
        # Determine if the attack was successful
        Q5 = "Is there evidence of users clicking the malicious link?"
        Q5_answer = (
            "Yes" if all_network_events.filter(
                pl.col("RemoteUrl") == self.phishing_sender["PhishingURL"]
            ).height > 0 else "No"
        )
        questions.append(Q5)
        answers.append(Q5_answer)
        
        # Identify compromised assets
        Q6 = "Which devices connected to the malicious URL after receiving the phishing email?"
        Q6_answer = (
            all_network_events
            .filter(pl.col("RemoteUrl") == self.phishing_sender["PhishingURL"])
            .select("DeviceName")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q6)
        answers.append(Q6_answer)
        
        # Technical indicators of compromise
        Q7 = "What is the malicious URL users were directed to?"
        Q7_answer = self.phishing_sender["PhishingURL"]
        questions.append(Q7)
        answers.append(Q7_answer)
        
        Q8 = "What is the IP address the phishing link resolves to?"
        Q8_answer = self.phishing_sender["PhishingIP"]
        questions.append(Q8)
        answers.append(Q8_answer)
        
        # Attack timeline analysis
        Q9 = "What was the time gap between the first phishing email and the first user click?"
        first_email_time = all_email_events.filter(
            pl.col("SenderMailFromAddress") == self.phishing_sender["AccountUpn"]
        ).select("Timestamp").min().item(0, 0)
        
        first_click_time = all_network_events.filter(
            pl.col("RemoteUrl") == self.phishing_sender["PhishingURL"]
        ).select("Timestamp").min().item(0, 0)
        
        time_diff = (first_click_time - first_email_time).total_seconds() / 60 if first_email_time and first_click_time else None
        Q9_answer = f"{round(time_diff, 2)} minutes" if time_diff is not None else "No clicks detected"
        questions.append(Q9)
        answers.append(Q9_answer)
        
        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df