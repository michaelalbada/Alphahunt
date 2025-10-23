import random
from datetime import datetime, timedelta
from faker import Faker
from tqdm import tqdm

from ..utils import generate_email_events, generate_outbound_network_events, generate_aad_sign_in_events
import polars as pl

class PhishingForInformationAttackGenerator:
    def __init__(self, benign_data, attacker):
        self.fake = Faker()
        self.benign_data = benign_data
        self.victims = self.benign_data["identity_info"]
        self.attacker_identity = attacker
        # TODO: Fill this in with more volume/realistic subjects 
        self.phishing_subject = "Urgent: Verify your account details"
        self.data = {}

    def generate_phishing_for_information(self):  
        phishing_email_events = []
        campaign_time = self.fake.date_time_between(
            start_date=datetime.today() - timedelta(days=30),
            end_date=datetime.today()
        )

        outbound_events = []
        all_victims = []
        aad_sign_in_events = []

        for victim in tqdm(self.victims.to_dicts(), desc="Generating phishing for information events"):
            event_time = campaign_time + timedelta(seconds=random.randint(0, 600))
            email_event = generate_email_events(
                identity_row_sender=self.attacker_identity,
                identity_row_recipient=victim,
                timestamp=event_time,
                in_network=False,
                fake=self.fake,
                know_sender=True,
                subject=self.phishing_subject,
            )
            phishing_email_events.append(email_event)

            if random.random() < 1.0:
                victim_upn = victim["AccountUpn"]
                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim_upn)
                )
                user_device = user_devices.sample(1).to_dicts()[0]

                click_time = event_time + timedelta(seconds=random.randint(60, 600))
                outbound_event = generate_outbound_network_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=click_time,
                    fake=self.fake,
                    remote_ip=self.attacker_identity["SenderIPv4"],
                    remote_url=f"{self.fake.domain_name()}",
                    remote_port=443
                )
                outbound_events.append(outbound_event)
                all_victims.append(victim)

                sign_in_time = click_time + timedelta(seconds=random.randint(60, 600))
                attacker_sign_in_event = generate_aad_sign_in_events(
                    identity_row=self.attacker_identity,
                    timestamp=sign_in_time,
                    fake=self.fake,
                    ip_address=self.attacker_identity["SenderIPv4"]
                )
                aad_sign_in_events.append(attacker_sign_in_event)

        self.victims = pl.DataFrame(all_victims)

        phishing_emails_df = pl.DataFrame(phishing_email_events)
        if phishing_emails_df.height > 0:
            phishing_emails_df = phishing_emails_df.sort("Timestamp")

        outbound_events_df = pl.DataFrame(outbound_events)
        if outbound_events_df.height > 0:
            outbound_events_df = outbound_events_df.sort("Timestamp")

        aad_sign_in_events_df = pl.DataFrame(aad_sign_in_events)
        if aad_sign_in_events_df.height > 0:
            aad_sign_in_events_df = aad_sign_in_events_df.sort("Timestamp")

        self.data["email_events"] = phishing_emails_df
        self.data["aad_sign_in_events_beta"] = aad_sign_in_events_df
        self.data["device_network_events"] = outbound_events_df

        last_event_time = max(
            phishing_emails_df.select(pl.col("Timestamp").max()).to_series().item(),
            outbound_events_df.select(pl.col("Timestamp").max()).to_series().item(),
            aad_sign_in_events_df.select(pl.col("Timestamp").max()).to_series().item()
        )

        return (
            self.data,
            self.victims,
            last_event_time
        )

    def generate_question_answer_pairs(self): 

        all_email_events = pl.concat([self.benign_data["email_events"], self.data["email_events"]])
        all_aad_sign_in_events = pl.concat([self.benign_data["aad_sign_in_events_beta"], self.data["aad_sign_in_events_beta"]])
        all_outbound_events = pl.concat([self.benign_data["device_network_events"], self.data["device_network_events"]])
        all_outbound_events = all_outbound_events.filter(pl.col("ActionType") == "OutboundConnection")

        questions = []
        answers = []

        Q1 = "How many total emails were sent in this network?"
        Q1_answer = all_email_events.height
        questions.append(Q1)
        answers.append(Q1_answer)

        Q2 = "Is there an email that was sent to at least 10 users, if so what is the subject?"
        Q2_answer = self.phishing_subject
        questions.append(Q2)
        answers.append(Q2_answer)

        Q3 = "What is the email address for this email?"
        sender_addresses = all_email_events.filter(pl.col("Subject") == self.phishing_subject).select("SenderFromAddress").unique()
        Q3_answer = sender_addresses.select(pl.col("SenderFromAddress")).to_series().item(0) if sender_addresses.height > 0 else None
        questions.append(Q3)
        answers.append(Q3_answer)

        Q4 = "How many unique recipients received the phishing email?"
        phishing_emails = all_email_events.filter(pl.col("Subject") == self.phishing_subject)
        if "RecipientEmailAddress" in phishing_emails.columns:
            Q4_answer = phishing_emails.select(pl.col("RecipientEmailAddress").unique()).height
        else:
            Q4_answer = "RecipientEmailAddress column not found"
        questions.append(Q4)
        answers.append(Q4_answer)

        Q5 = "How many unique sign-in events were generated by the attacker?"
        Q5_answer = all_aad_sign_in_events.filter(pl.col("AccountUpn") == self.attacker_identity["AccountUpn"]).height
        questions.append(Q5)
        answers.append(Q5_answer)

        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df
