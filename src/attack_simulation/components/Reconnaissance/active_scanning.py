import pandas as pd
import polars as pl
import random
from faker import Faker
from datetime import datetime, timedelta
from ..utils import generate_inbound_network_events
from src.benign_simulation.benign import BenignActivityGenerator
from tqdm import tqdm

class ActiveScanningAttackGenerator:
    def __init__(self, benign_data, attacker):
        self.fake = Faker()
        self.victims = None
        self.num_users_scanned = None
        self.benign_data = benign_data
        self.active_scan_data = None
        self.attacker_identity = attacker

    def generate_active_scan(self):

        inbound_events = []
        self.num_users_scanned = len(self.benign_data['identity_info'])
        end_date = datetime.today()
        start_date = end_date - timedelta(days=30)
        scan_time = self.fake.date_time_between(start_date=start_date, end_date=end_date)
        all_victims = []
        for _ in range(self.num_users_scanned):

            remaining_users = self.benign_data['identity_info'].filter(
                ~self.benign_data['identity_info']['AccountUpn'].is_in(
                    [v['AccountUpn'] for v in all_victims]
                )
            )
            scanned = remaining_users.sample(n=1).to_dicts()[0]
            all_victims.append(scanned)
            user_devices = self.benign_data["device_info"].filter(
                pl.col("LoggedOnUsers").str.contains(scanned["AccountUpn"])
            )
            user_device = user_devices.sample(n=1).to_dicts()[0]
            for _ in range(random.randint(5, 10)):
                event_time = scan_time + timedelta(seconds=random.randint(0, 10))
                inbound_event = generate_inbound_network_events(
                    identity_row=scanned,
                    device_row=user_device,
                    timestamp=event_time,
                    fake=self.fake,
                    remote_ip=self.attacker_identity["SenderIPv4"],
                    remote_url=self.attacker_identity["AccountDomain"],
                    remote_port=random.randint(1, 65535),
                )
                inbound_events.append(inbound_event)
        self.victims = pl.DataFrame(all_victims)
        df = pl.DataFrame(inbound_events)
        data = {'device_network_events': df}
        self.active_scan_data = df
        last_scan_time = df['Timestamp'].max()
        return (data, self.victims, last_scan_time)

    def generate_question_answer_pairs(self):
        all_inbound_events = self.benign_data['device_network_events']
        all_inbound_events = all_inbound_events.filter(pl.col("ActionType") == "InboundConnection")
        all_inbound_events = pl.concat([all_inbound_events, self.active_scan_data])

        questions, answers = [], []

        Q1 = "How many unique inbound network ip addresses were used to connect to the network?"
        Q1_answer = all_inbound_events["RemoteIP"].n_unique()
        questions.append(Q1); answers.append(Q1_answer)

        ip_counts = all_inbound_events.group_by("RemoteIP").agg(pl.count())
        Q2 = "How many inbound network ip addresses connected to the network more than 20 times?"
        Q2_answer = ip_counts.filter(pl.col("count") > 20).height
        questions.append(Q2); answers.append(Q2_answer)

        Q3 = "What is the ip address that connected to the network the most?"
        ip_counts = ip_counts.sort("count", descending=True)
        Q3_answer = ip_counts[0, "RemoteIP"]
        questions.append(Q3); answers.append(Q3_answer)

        Q4 = "What is the number of ports that were used by this ip address to connect to the network?"
        Q4_answer = all_inbound_events.filter(pl.col("RemoteIP") == Q3_answer)["RemotePort"].n_unique()
        questions.append(Q4); answers.append(Q4_answer)

        Q5 = "What is the number of unique users that were scanned by this ip address?"
        Q5_answer = all_inbound_events.filter(pl.col("RemoteIP") == Q3_answer)["DeviceName"].n_unique()
        questions.append(Q5); answers.append(Q5_answer)

        Q6 = "What is the time frame from the first scan to the last scan?"
        min_time = all_inbound_events.filter(pl.col("RemoteIP") == Q3_answer)["Timestamp"].min()
        max_time = all_inbound_events.filter(pl.col("RemoteIP") == Q3_answer)["Timestamp"].max()
        Q6_answer = max_time - min_time
        questions.append(Q6); answers.append(Q6_answer)

        Q7 = "What is the remote url that was used to connect to the network?"
        unique_urls = all_inbound_events.filter(pl.col("RemoteIP") == Q3_answer)["RemoteUrl"].unique()
        Q7_answer = unique_urls[0] if len(unique_urls) else None
        questions.append(Q7); answers.append(Q7_answer)

        Q8 = "What is the IP address of the attacker?"
        Q8_answer = self.attacker_identity["SenderIPv4"]
        questions.append(Q8); answers.append(Q8_answer)

        Q9 = "What is the domain of the attacker?"
        Q9_answer = self.attacker_identity["AccountDomain"]
        questions.append(Q9); answers.append(Q9_answer)

        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        qa_df = qa_df.with_columns(
            pl.col("Question").cast(pl.Utf8),
            pl.col("Answer").cast(pl.Utf8)
        )
        return qa_df
