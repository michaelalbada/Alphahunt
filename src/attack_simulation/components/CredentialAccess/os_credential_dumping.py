import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm
from ..utils import generate_device_process_events, generate_device_file_events

class OSCredentialDumpingAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time):
        self.fake = Faker()
        self.benign_data = benign_data
        self.victims = victims
        self.attacker = attacker
        self.last_scan_time = last_scan_time
        self.data = None
        
        # Credential dumping tools and commands
        self.credential_dump_tools = [
            {
                "tool": "mimikatz.exe",
                "commands": [
                    "privilege::debug sekurlsa::logonpasswords",
                    "sekurlsa::logonpasswords",
                    "sekurlsa::wdigest",
                    "lsadump::sam",
                    "lsadump::secrets"
                ],
                "parent_process": "powershell.exe"
            },
            {
                "tool": "procdump.exe",
                "commands": [
                    "-ma lsass.exe lsass.dmp",
                    "-ma -accepteula lsass.exe lsass.dmp"
                ],
                "parent_process": "cmd.exe"
            },
            {
                "tool": "pwdump.exe",
                "commands": [
                    ""
                ],
                "parent_process": "cmd.exe"
            },
            {
                "tool": "wce.exe",
                "commands": [
                    "-w",
                    "-o output.txt"
                ],
                "parent_process": "cmd.exe"
            },
            {
                "tool": "gsecdump.exe",
                "commands": [
                    "-a"
                ],
                "parent_process": "cmd.exe"
            }
        ]
        
        # PowerShell commands for credential dumping
        self.powershell_commands = [
            "Invoke-Mimikatz -DumpCreds",
            "Get-Process lsass | Out-MiniDump -DumpFilePath C:\\temp\\lsass.dmp",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
            "Add-Type -AssemblyName System.Security; [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'LocalMachine')",
            "Invoke-Command -ScriptBlock {Set-MpPreference -DisableRealtimeMonitoring $true}",
            "Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full'"
        ]
        
        # Potential dump file paths
        self.dump_file_paths = [
            "C:\\temp\\lsass.dmp",
            "C:\\Windows\\Temp\\lsass.dmp",
            "C:\\Users\\Public\\lsass.dmp",
            "C:\\ProgramData\\lsass.dmp",
            "C:\\Users\\Administrator\\Desktop\\dump.bin",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\extracted_creds.txt"
        ]
        
        # Suspicious access to Windows registry locations containing credentials
        self.registry_keys = [
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "HKLM\\SECURITY\\Cache",
            "HKLM\\SAM\\SAM\\Domains\\Account",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
            "HKLM\\SECURITY\\Policy\\Secrets"
        ]

    def generate_os_credential_dumping_attack(self):
        device_process_events = []
        device_file_events = []
        
        campaign_time = self.fake.date_time_between(start_date=self.last_scan_time, end_date=datetime.today())
        
        targeted_accounts = []
        
        selected_victims = random.sample(
            list(self.victims.iter_rows(named=True)), 
            min(random.randint(1, 5), len(self.victims))
        )
        
        for victim in tqdm(selected_victims, desc="Generating credential dumping events"):
            targeted_accounts.append(victim["AccountUpn"])

            devices = self.benign_data["device_info"].filter(pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"]))
            device = devices.sample(n=1).to_dicts()[0]
            
            # STAGE 1: Initial Process Execution (e.g., PowerShell or cmd)
            initial_timestamp = campaign_time + timedelta(seconds=random.randint(0, 60))
            initial_process = random.choice(["cmd.exe", "powershell.exe"])
            
            initial_process_event = generate_device_process_events(
                identity_row=victim,
                device_row=device,
                timestamp=initial_timestamp,
                fake=self.fake,
                file_name=initial_process,
                process_command_line=f"{initial_process}"
            )
            device_process_events.append(initial_process_event)
            
            # STAGE 2: Tool Execution or PowerShell Command
            use_powershell_command = random.choice([True, False])
            
            if use_powershell_command and initial_process == "powershell.exe":
                ps_timestamp = initial_timestamp + timedelta(seconds=random.randint(5, 30))
                ps_command = random.choice(self.powershell_commands)
                
                ps_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=device,
                    timestamp=ps_timestamp,
                    fake=self.fake,
                    file_name="powershell.exe",
                    process_command_line=f"powershell.exe -EncodedCommand {self.fake.pystr()} -WindowStyle Hidden {ps_command}"
                )
                device_process_events.append(ps_event)
                
                if "lsass.dmp" in ps_command or "MiniDump" in ps_command:
                    dump_file_path = random.choice(self.dump_file_paths)
                    file_timestamp = ps_timestamp + timedelta(seconds=random.randint(2, 10))
                    
                    dump_file_event = generate_device_file_events(
                        identity_row=victim,
                        device_row=device,
                        timestamp=file_timestamp,
                        fake=self.fake
                    )
                    dump_file_event["ActionType"] = "FileCreated"
                    dump_file_event["FileName"] = dump_file_path.split("\\")[-1]
                    dump_file_event["FolderPath"] = "\\".join(dump_file_path.split("\\")[:-1])
                    dump_file_event["FileSize"] = random.randint(10000000, 50000000)
                    
                    device_file_events.append(dump_file_event)
            else:
                tool_data = random.choice(self.credential_dump_tools)
                tool_timestamp = initial_timestamp + timedelta(seconds=random.randint(5, 30))

                tool_creation_event = generate_device_file_events(
                    identity_row=victim,
                    device_row=device,
                    timestamp=tool_timestamp,
                    fake=self.fake
                )
                tool_creation_event["ActionType"] = "FileCreated"
                tool_creation_event["FileName"] = tool_data["tool"]
                tool_creation_event["FolderPath"] = random.choice(["C:\\temp", "C:\\Users\\Public", "C:\\Windows\\Temp", "C:\\ProgramData"])
                
                device_file_events.append(tool_creation_event)

                command = random.choice(tool_data["commands"])
                tool_exec_timestamp = tool_timestamp + timedelta(seconds=random.randint(3, 15))
                
                tool_exec_event = generate_device_process_events(
                    identity_row=victim,
                    device_row=device,
                    timestamp=tool_exec_timestamp,
                    fake=self.fake,
                    file_name=tool_data["tool"],
                    process_command_line=f"{tool_data['tool']} {command}"
                )
                tool_exec_event["InitiatingProcessFileName"] = tool_data["parent_process"]
                
                device_process_events.append(tool_exec_event)
                
                if "lsass" in command or tool_data["tool"] in ["mimikatz.exe", "procdump.exe"]:
                    dump_file_path = random.choice(self.dump_file_paths)
                    dump_timestamp = tool_exec_timestamp + timedelta(seconds=random.randint(2, 10))
                    
                    dump_file_event = generate_device_file_events(
                        identity_row=victim,
                        device_row=device,
                        timestamp=dump_timestamp,
                        fake=self.fake
                    )
                    dump_file_event["ActionType"] = "FileCreated"
                    dump_file_event["FileName"] = dump_file_path.split("\\")[-1]
                    dump_file_event["FolderPath"] = "\\".join(dump_file_path.split("\\")[:-1])
                    dump_file_event["FileSize"] = random.randint(10000000, 50000000)  # 10-50 MB
                    
                    device_file_events.append(dump_file_event)
        
        self.data = {
            "device_process_events": pl.DataFrame(device_process_events).sort("Timestamp") if device_process_events else pl.DataFrame(),
            "device_file_events": pl.DataFrame(device_file_events).sort("Timestamp") if device_file_events else pl.DataFrame()
        }
        
        targeted_accounts = self.victims.filter(pl.col("AccountUpn").is_in(targeted_accounts)) if targeted_accounts else pl.DataFrame()

        all_timestamps = []
        for df in self.data.values():
            if not df.is_empty() and "Timestamp" in df.columns:
                all_timestamps.extend(df.get_column("Timestamp").to_list())
                
        last_event_time = max(all_timestamps) if all_timestamps else None
        
        return self.data, targeted_accounts, last_event_time
    
    def generate_question_answer_pairs(self):
        questions = []
        answers = []
        
        # Q1: How many victims were targeted in this credential dumping attack?
        questions.append("How many victims were targeted in this credential dumping attack?")
        
        # Count unique accounts in process events
        if "device_process_events" in self.data and not self.data["device_process_events"].is_empty():
            unique_accounts = self.data["device_process_events"].select(pl.col("AccountUpn").n_unique()).item()
        else:
            unique_accounts = 0
            
        answers.append(unique_accounts)
        
        # Q2: Which credential dumping tools were used in the attack?
        questions.append("Which credential dumping tools were used in the attack?")
        
        # Extract tool names from process events
        tools_used = []
        if "device_process_events" in self.data and not self.data["device_process_events"].is_empty():
            for event in self.data["device_process_events"].iter_rows(named=True):
                cmd = event.get("ProcessCommandLine", "")
                for tool in [t["tool"] for t in self.credential_dump_tools]:
                    if tool in cmd:
                        tools_used.append(tool)
                
                # Check for PowerShell commands
                if "powershell.exe" in cmd:
                    for ps_cmd in self.powershell_commands:
                        if ps_cmd in cmd:
                            tools_used.append("PowerShell credential dumping")
                            break
        
        tools_used = list(set(tools_used))  # Remove duplicates
        tools_used = ", ".join(tools_used) if isinstance(tools_used, list) else tools_used
        if not tools_used:
            tools_used = "No tools detected"
            
        answers.append(tools_used)
        
        # Q3: What is the most common type of file created during the attack?
        questions.append("What is the most common type of file created during the attack?")
        
        if "device_file_events" in self.data and not self.data["device_file_events"].is_empty():
            file_events = self.data["device_file_events"].filter(pl.col("ActionType") == "FileCreated")
            if not file_events.is_empty():
                # Extract file extensions and count them
                file_types = file_events.with_columns(
                    pl.col("FileName").str.split(".").list.last().alias("FileExtension")
                )
                
                if file_types.height > 0:
                    type_counts = file_types.group_by("FileExtension").count().sort("count", descending=True)
                    most_common_type = type_counts.row(0)[0] if type_counts.height else "N/A"
                else:
                    most_common_type = "N/A"
            else:
                most_common_type = "No files created"
        else:
            most_common_type = "No file events recorded"
            
        answers.append(most_common_type)
        
        # Q4: How much time (in seconds) elapsed between the first and last event in the attack?
        questions.append("How much time (in seconds) elapsed between the first and last event in the attack?")
        
        all_timestamps = []
        for df in self.data.values():
            if not df.is_empty() and "Timestamp" in df.columns:
                all_timestamps.extend(df.get_column("Timestamp").to_list())
                
        if all_timestamps:
            duration = (max(all_timestamps) - min(all_timestamps)).total_seconds()
        else:
            duration = "N/A"
            
        answers.append(duration)
        
        # Q5: What processes were used to initiate credential dumping?
        questions.append("What processes were used to initiate credential dumping?")
        
        initiating_processes = []
        if "device_process_events" in self.data and not self.data["device_process_events"].is_empty():
            for event in self.data["device_process_events"].iter_rows(named=True):
                if "InitiatingProcessFileName" in event:
                    initiating_processes.append(event["InitiatingProcessFileName"])
                    
            initiating_processes = list(set(initiating_processes))
            if not initiating_processes:
                initiating_processes = "No initiating processes detected"
        else:
            initiating_processes = "No process events recorded"
            
        answers.append(", ".join(initiating_processes) if isinstance(initiating_processes, list) else initiating_processes)

        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
