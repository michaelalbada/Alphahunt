import random
import string
from datetime import datetime, timedelta
import pandas as pd
from faker import Faker
from tqdm import tqdm
import polars as pl

from ..utils import (
    generate_device_process_events,
    generate_device_file_events
)

class ContentInjectionAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.victims = victims
        self.last_scan_time = last_scan_time
        self.num_injections_range = (2,4)
        self.data = None
        self.phishing_sender = attacker

    def generate_data_content_injection_attack(self):  
        process_events = []
        file_events = []
        compromised_victims = set()
        campaign_time = self.fake.date_time_between(start_date=self.last_scan_time, end_date=datetime.today())
        victim_selected = False

        for victim in tqdm(self.victims.to_dicts(), desc="Generating content injection events for victims"):
            if random.random() < 0.3 or not victim_selected:
                victim_selected = True
                compromised_victims.add(victim["AccountUpn"])

                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                user_device = user_devices.sample(n=1).to_dicts()[0]

                target_file = self.fake.file_name(extension=random.choice(["docx", "xlsx", "pdf"]))
                num_injections = random.randint(self.num_injections_range[0], self.num_injections_range[1])

                for i in range(num_injections):
                    injection_time = campaign_time + timedelta(seconds=random.randint(0, 300) + i * random.randint(30, 90))
                    payload = "Payload_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    # need to update this to a more realistic command
                    injection_command = f"injector.exe -f {target_file} -p {payload}"

                    proc_event = generate_device_process_events(
                        identity_row=self.phishing_sender,
                        device_row=user_device,
                        timestamp=injection_time,
                        fake=self.fake,
                        file_name=target_file,
                        process_command_line=injection_command,
                    )
                    process_events.append(proc_event)

                    file_injection_time = injection_time + timedelta(seconds=random.randint(5, 30))
                    file_event = generate_device_file_events(
                        identity_row=self.phishing_sender,
                        device_row=user_device,
                        timestamp=file_injection_time,
                        fake=self.fake,
                    )
                    file_event["ActionType"] = "FileModified"
                    file_event["FileName"] = target_file
                    file_events.append(file_event)

        data = {
            "process_events": pl.DataFrame(process_events).sort("Timestamp") if process_events else pl.DataFrame(),
            "file_events": pl.DataFrame(file_events).sort("Timestamp") if file_events else pl.DataFrame()
        }
        self.data = data

        last_event_time = max(
            data["process_events"]["Timestamp"].max(),
            data["file_events"]["Timestamp"].max(),
        )
        compromised_victims_list = list(compromised_victims)
        compromised_victims_df = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims_list)) if compromised_victims_list else pl.DataFrame()
        return data, compromised_victims_df, last_event_time

    def generate_question_answer_pairs(self):

        all_process_events = pl.concat([
            self.benign_data["device_process_events"],
            self.data["process_events"]
        ])
        all_file_events = pl.concat([
            self.benign_data.get("file_events", pl.DataFrame()),
            self.data["file_events"]
        ])

        questions = []
        answers = []

        Q1 = "How many processes have a -p payload associated?"
        Q1_answer = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("-p")
        ).shape[0]
        questions.append(Q1)
        answers.append(Q1_answer)

        Q2 = "For these processes what injection executable is being used by the attacker?"
        Q2_answer = ", ".join(
            all_process_events
            .filter(pl.col("ProcessCommandLine").str.contains("-p"))
            .with_columns(
                pl.col("ProcessCommandLine")
                .str.extract(r"^(\S+)")
                .alias("executable")
            )
            .select("executable")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q2)
        answers.append(Q2_answer)

        Q4 = "What are the target files that were modified by the injection events?"
        Q4_answer = ", ".join(
            all_process_events
            .filter(pl.col("ProcessCommandLine").str.contains("-p"))
            .select("FileName")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q4)
        answers.append(Q4_answer)

        Q5 = "How many times were files modified by the content injection?"
        Q5_answer = all_file_events.filter(
            (pl.col("ActionType") == "FileModified") &
            (pl.col("InitiatingProcessAccountDomain") == self.phishing_sender['AccountDomain'])
        ).shape[0]
        questions.append(Q5)
        answers.append(Q5_answer)

        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df
