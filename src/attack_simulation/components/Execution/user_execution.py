import random
from datetime import datetime, timedelta
from pathlib import Path
import polars as pl
from tqdm import tqdm
from faker import Faker

from ..utils import (
    generate_device_file_events,
    generate_device_process_events,
    generate_outbound_network_events
)

class UserExecutionAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.victims = victims
        self.fake = Faker()
        self.benign_data = benign_data
        self.attacker = attacker
        self.last_scan_time = last_scan_time
        self.malicious_file = self.fake.file_name(extension="exe")
        self.data = {}

    def generate_user_execution_attack(self):
        data = {}
        file_events = []
        process_events = []
        network_events = []

        campaign_start_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        
        compromised_victims = []
        for victim in tqdm(self.victims.to_dicts(), desc="Generating user execution events"):
            
            execution_time = campaign_start_time + timedelta(minutes=random.randint(5, 60))
            
            compromised_victims.append(victim["AccountUpn"])
            
            user_devices = self.benign_data["device_info"].filter(
                pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
            )
            device_info = user_devices.sample(n=1).to_dicts()[0]

            file_event = generate_device_file_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=execution_time,
                fake=self.fake
            )
            
            file_event["ActionType"] = "FileCreated"
            file_event["FileName"] = self.malicious_file
            file_event["FolderPath"] = f"C:\\Users\\{victim['AccountName']}\\Downloads\\"
            
            file_events.append(file_event)

            process_time = execution_time + timedelta(seconds=random.randint(2, 10))
            process_event = generate_device_process_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=process_time,
                fake=self.fake,
                file_name=Path(self.malicious_file).name,
                process_command_line=f"C:\\Users\\{victim['AccountName']}\\Downloads\\{self.malicious_file}"
            )
            process_events.append(process_event)
            
            callback_time = process_time + timedelta(seconds=random.randint(5, 20))
            callback_event = generate_outbound_network_events(
                identity_row=victim,
                device_row=device_info,
                timestamp=callback_time,
                fake=self.fake,
                remote_ip=self.attacker['ExternalServerIP'],
                remote_url=self.attacker['ExternalServerName'],
                remote_port=random.choice([443, 8080, 4444])
            )
            network_events.append(callback_event)
        
        if file_events:
            data["device_file_events"] = pl.DataFrame(file_events).sort("Timestamp")
        if process_events:
            data["device_process_events"] = pl.DataFrame(process_events).sort("Timestamp")
        if network_events:
            data["device_network_events"] = pl.DataFrame(network_events).sort("Timestamp")
        
        self.data = data
        
        all_timestamps = [ts for df in data.values() if "Timestamp" in df.columns for ts in df["Timestamp"].to_list()]
        last_event_time = max(all_timestamps) if all_timestamps else campaign_start_time
        
        compromised_victims_df = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims))
        
        return data, compromised_victims_df, last_event_time

    def generate_question_answer_pairs(self):
        # Combine benign and malicious events for analysis
        all_process_events = pl.concat([self.benign_data["device_process_events"], self.data.get("device_process_events", pl.DataFrame())])
        all_network_events = pl.concat([
            self.benign_data["device_network_events"].filter(pl.col("ActionType") == "OutboundConnection"), 
            self.data.get("device_network_events", pl.DataFrame())
        ])
        all_file_events = pl.concat([self.benign_data["device_file_events"], self.data.get("device_file_events", pl.DataFrame())])
        
        questions = []
        answers = []
        
        Q1 = "What is the total count of executable files created in user download folders?"
        Q1_answer = (
            all_file_events
            .filter(
                (pl.col("ActionType") == "FileCreated") & 
                (pl.col("FolderPath").str.contains("Downloads")) &
                (pl.col("FileName").str.ends_with(".exe"))
            )
            .height
        )
        questions.append(Q1)
        answers.append(Q1_answer)
        
        Q2 = "Identify all users who ran executable files from their download folders"
        Q2_answer = ", ".join(
            all_process_events
            .filter(
                pl.col("ProcessCommandLine").str.contains("Downloads.*\\.exe", literal=False)
            )
            .select("AccountUpn")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q2)
        answers.append(Q2_answer)

        Q3 = f"Count the unique devices that connected to external servers after the execution of '{self.malicious_file}'"
        Q3_answer = (
            all_network_events
            .filter(
                pl.col("Timestamp") > all_process_events
                .filter(pl.col("FileName") == Path(self.malicious_file).name)
                .select(pl.min("Timestamp")).item()
            )
            .select("DeviceName")
            .unique()
            .height
        )
        questions.append(Q3)
        answers.append(Q3_answer)

        Q5 = "What is the name of the malicious file executed?"
        Q5_answer = self.malicious_file
        questions.append(Q5)
        answers.append(Q5_answer)
        
        Q6 = "List all IP addresses that were connected to after malicious file execution"
        Q6_answer = ", ".join(
            self.data.get("device_network_events", pl.DataFrame())
            .filter(
                pl.col("Timestamp") > all_process_events
                .filter(pl.col("FileName") == Path(self.malicious_file).name)
                .select(pl.min("Timestamp")).item()
            )
            .select("RemoteIP")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q6)
        answers.append(Q6_answer)

        Q7 = "What is the average time delay between malicious file creation and execution?"
        Q7_answer = (
            (all_process_events
             .filter(pl.col("FileName") == Path(self.malicious_file).name)
             .select("Timestamp").to_series().mean() -
             all_file_events
             .filter(pl.col("FileName") == self.malicious_file)
             .select("Timestamp").to_series().mean()).total_seconds()
        )
        questions.append(Q7)
        answers.append(Q7_answer)


        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)

        return qa_df
