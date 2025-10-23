from ..utils import generate_device_process_events
import polars as pl
from faker import Faker
import random
from datetime import datetime, timedelta
from tqdm import tqdm

class AccountAccessRemovalAttackGenerator:
    def __init__(self, benign_data, victims, attacker, last_scan_time, recon_commands=None, admin_processes=None, removal_commands=None, cleanup_commands=None, recon_time_range=None, removal_time_range=None, cleanup_time_range=None, victim_selection_probability=None):
        self.fake = Faker()
        self.benign_data = benign_data
        self.victims = victims
        self.attacker = attacker
        self.last_scan_time = last_scan_time
        self.admin_processes = admin_processes or [
            'powershell.exe', 'cmd.exe', 'net.exe', 'dsquery.exe', 'dsmod.exe'
        ]
        self.removal_commands = removal_commands or [
            "Disable-ADAccount -Identity {account}",
            "net user {account} /active:no",
            "Remove-ADGroupMember -Identity 'Domain Admins' -Members {account}",
            "Remove-ADGroupMember -Identity 'Enterprise Admins' -Members {account}"
        ]
        self.cleanup_commands = cleanup_commands or [
            "wevtutil cl Security",
            "wevtutil cl System",
            "wevtutil cl Application",
            "Remove-EventLog -LogName Security",
            "Clear-EventLog -LogName System"
        ]
        self.recon_time_range = recon_time_range or [0, 300]
        self.removal_time_range = removal_time_range or [300, 600]
        self.cleanup_time_range = cleanup_time_range or [600, 900]
        self.victim_selection_probability = victim_selection_probability if victim_selection_probability is not None else 0.8
        self.data = None
        self.recon_commands = recon_commands or [
            "net user /domain",
            "Get-ADUser -Filter * -Properties *",
            "net group /domain",
            "Get-ADGroup -Filter *",
            "Get-ADUser -Filter * -Properties MemberOf",
            "net localgroup",
            "Get-LocalUser",
            "Get-LocalGroupMember -Group Administrators"
        ]

    def generate_account_access_removal_attack(self):
        process_events = []
        compromised_accounts = set()
        successful_process = False
        
        campaign_time = self.fake.date_time_between(start_date=self.last_scan_time, end_date=datetime.today())
        
        # Step 1: Reconnaissance events
        for victim in tqdm(self.victims.iter_rows(named=True), desc="Generating account access removal events"):
            # Continue processing victims until we get at least one success, then use probability
            if not successful_process or random.random() < self.victim_selection_probability:
                user_devices = self.benign_data["device_info"].filter(
                    pl.col("LoggedOnUsers").str.contains(victim["AccountUpn"])
                )
                
                if user_devices.height > 0:
                    successful_process = True
                    compromised_accounts.add(victim["AccountUpn"])
                    
                    user_device = user_devices.sample(n=1)
                    user_device = dict(zip(user_device.columns, user_device.row(0)))
                    
                    # Generate recon events
                    for cmd in self.recon_commands:
                        recon_time = campaign_time + timedelta(seconds=random.randint(self.recon_time_range[0], self.recon_time_range[1]))
                        process_event = generate_device_process_events(
                            identity_row=self.attacker,
                            device_row=user_device,
                            timestamp=recon_time,
                            fake=self.fake,
                            file_name=random.choice(self.admin_processes),
                            process_command_line=cmd
                        )
                        process_events.append(process_event)
                    
                    # Generate account removal events
                    for cmd_template in self.removal_commands:
                        cmd = cmd_template.format(account=victim['AccountUpn'])
                        removal_time = campaign_time + timedelta(seconds=random.randint(self.removal_time_range[0], self.removal_time_range[1]))
                        process_event = generate_device_process_events(
                            identity_row=self.attacker,
                            device_row=user_device,
                            timestamp=removal_time,
                            fake=self.fake,
                            file_name=random.choice(self.admin_processes),
                            process_command_line=cmd
                        )
                        process_events.append(process_event)
                    
                    # Generate cleanup events
                    for cmd in self.cleanup_commands:
                        cleanup_time = campaign_time + timedelta(seconds=random.randint(self.cleanup_time_range[0], self.cleanup_time_range[1]))
                        process_event = generate_device_process_events(
                            identity_row=self.attacker,
                            device_row=user_device,
                            timestamp=cleanup_time,
                            fake=self.fake,
                            file_name=random.choice(self.admin_processes),
                            process_command_line=cmd
                        )
                        process_events.append(process_event)

        # Ensure we processed at least one victim
        if not successful_process:
            raise ValueError("No victims with associated devices were found. At least one victim with devices is required for account access removal attack.")

        # Convert to DataFrame with proper schema
        if process_events:
            process_df = pl.DataFrame(process_events)
            
            # Ensure all required columns are present with empty strings instead of None
            required_columns = [
                "Timestamp", "DeviceName", "AccountUpn", "FileName", 
                "ProcessCommandLine", "ProcessId", "ParentProcessId", 
                "InitiatingProcessAccountUpn", "InitiatingProcessFileName"
            ]
            for col in required_columns:
                if col not in process_df.columns:
                    process_df = process_df.with_columns(pl.lit("").alias(col))
                else:
                    # Replace None values with empty string
                    process_df = process_df.with_columns(
                        pl.col(col).fill_null("")
                    )
        else:
            # Create empty DataFrame with required schema
            process_df = pl.DataFrame({
                "Timestamp": [],
                "DeviceName": [],
                "AccountUpn": [],
                "FileName": [],
                "ProcessCommandLine": [],
                "ProcessId": [],
                "ParentProcessId": [],
                "InitiatingProcessAccountUpn": [],
                "InitiatingProcessFileName": []
            })

        # Store process events for QA generation
        self.process_events = process_df
        
        # Generate QA pairs
        qa_df = self.generate_question_answer_pairs()
        
        return {
            "device_process_events": process_df,
            "network_events": pl.DataFrame(),  # Empty DataFrame for network events
            "file_events": pl.DataFrame()      # Empty DataFrame for file events
        }, self.victims, campaign_time, qa_df

    def generate_question_answer_pairs(self):
        questions = []
        answers = []
        df = self.process_events

        # Q1: How many unique accounts had their password updated?
        # Look for commands that indicate a password update (e.g., 'net user ... /active:no' or similar)
        password_update_mask = df['ProcessCommandLine'].str.contains('password') if 'ProcessCommandLine' in df.columns else pl.Series([], pl.Boolean)
        accounts_with_pw_update = set(df.filter(password_update_mask)['AccountUpn'].unique()) if password_update_mask.sum() > 0 else set()
        questions.append("How many unique accounts had their password updated?")
        answers.append(len(accounts_with_pw_update))

        # Q2: How many accounts were affected by access removal?
        questions.append("How many accounts were affected by access removal?")
        answers.append(len(df['AccountUpn'].unique()) if 'AccountUpn' in df.columns else 0)

        # Q3: What is the command used to change account access?
        removal_cmds = df['ProcessCommandLine'].unique().to_list() if 'ProcessCommandLine' in df.columns else []
        questions.append("What is the command used to change account access?")
        answers.append(", ".join(removal_cmds) if removal_cmds else "No removal commands found")

        # Q4: What types of access were removed?
        questions.append("What types of access were removed?")
        answers.append("Azure AD access and local account access")

        # Q5: What was the time range of the access removal events?
        questions.append("What was the time range of the access removal events?")
        if 'Timestamp' in df.columns and df.height > 0:
            # Convert to datetime if not already
            time_col = df['Timestamp']
            if time_col.dtype != pl.Datetime:
                time_col = time_col.str.strptime(pl.Datetime, format="%Y-%m-%d %H:%M:%S", strict=False)
            min_time = time_col.min()
            max_time = time_col.max()
            if min_time is not None and max_time is not None:
                answers.append(f"{max_time - min_time}")
            else:
                answers.append("No valid time range found")
        else:
            answers.append("No access removal events found")

        # Q6: Which tool was used for disabling accounts?
        tools_used = df['FileName'].unique().to_list() if 'FileName' in df.columns else []
        questions.append("Which tool was used for disabling accounts?")
        answers.append(", ".join(tools_used) if tools_used else "No tools found")

        # Q7: What accounts were targeted?
        questions.append("What accounts were targeted?")
        targeted_accounts = df['AccountUpn'].unique().to_list() if 'AccountUpn' in df.columns else []
        answers.append(", ".join(targeted_accounts) if targeted_accounts else "No accounts were targeted")

        # Q8: What was the pattern of access removal?
        questions.append("What was the pattern of access removal?")
        answers.append("Sequential removal of both Azure AD and local account access")

        return pl.DataFrame({"Question": questions, "Answer": answers}, strict=False)
