import polars as pl
from src.attack_simulation.components.attack_step_base import AttackStepBase
from src.utils.pydantic_models.qa import Question, Answer, QuestionAnswerPair, Difficulty, AnswerType, Language, ReturnType
from src.utils.pydantic_models.defender_xdr.device_registry_events import DeviceRegistryEvents
from pydantic import TypeAdapter
import random
from datetime import timedelta, datetime
from typing import Union
from src.utils.pydantic_helpers import build_dataframe_from_schema

class BootLogonAutostartExecutionAttackStep(AttackStepBase):
    """
    Simulates persistence via Boot or Logon Autostart Execution (e.g., Registry Run Keys).
    MITRE ATT&CK T1547
    """
    @property
    def DEFAULT_QA_YAML_PATH(self):
        return "src/attack_simulation/components/Persistence/boot_logon_autostart_execution_qa.yaml"

    @property
    def ANSWER_FUNCTIONS(self):
        return self.build_answer_functions()

    @property
    def XDR_MODEL_MAP(self):
        return {
            "device_registry_events": DeviceRegistryEvents
        }

    def generate_attack(self):
        if self.debug:
            self.log_info("[BootLogon] Starting attack generation for Boot/Logon Autostart Execution.")
        # Configurable or default values
        config_dict = self.config.dict()
        registry_keys = config_dict.get("common_registry_keys", [
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        ])
        if self.debug:
            self.log_info(f"[BootLogon] Using registry keys: {registry_keys}")
        value_names = config_dict.get("ValueNames", ["Malware", "Updater", "SystemTask", "Persistence", "AutoStart", "BackgroundTask"])
        value_data_templates = config_dict.get(
            "ValueDataTemplates",
            [r"C:\\Users\\{account_name}\\{exe}", r"C:\\Windows\\System32\\{exe}", r"C:\\ProgramData\\{exe}"]
        )
        exe_names = config_dict.get("ExeNames", [
            "malware.exe", "update.exe", "taskhost.exe", "svchost.exe", "explorer.exe", "chrome.exe", "powershell.exe", "cmd.exe"
        ])
        action_type = config_dict.get("ActionType", "SetValue")
        registry_value_type = config_dict.get("RegistryValueType", "REG_SZ")
        benign_data = self.config.benign_data
        device_info_df = benign_data.get("device_info", None)
        identity_info_df = benign_data.get("identity_info", None)
        fake = self.fake

        victims = self.config.victims
        victims_df = pl.DataFrame(victims) if not isinstance(victims, pl.DataFrame) else victims

        if self.debug:
            self.log_info(f"[BootLogon] Number of victims: {victims_df.height}")

        if device_info_df is not None:
            device_info_min = device_info_df.select(["DeviceId", "DeviceName", "LoggedOnUsers"])
            if device_info_min["LoggedOnUsers"].dtype == pl.List:
                device_info_min = device_info_min.explode("LoggedOnUsers")
            victims_df = victims_df.join(device_info_min, left_on="AccountUpn", right_on="LoggedOnUsers", how="left")
            if self.debug:
                self.log_info(f"[BootLogon] Joined victims with device_info. Resulting shape: {victims_df.shape}")

        n = victims_df.height
        if n == 0:
            self.log_warning("[BootLogon] No victims found. No registry events will be generated.")
            self.data = {"device_registry_events": pl.DataFrame()}
            return self.data, self.config.victims, self.config.last_scan_time

        rng = random.Random()
        from uuid import uuid4

        # Pre-generate random values for all rows (ensure variation)
        registry_key_col = [rng.choice(registry_keys) for _ in range(n)]
        if self.debug:
            self.log_info(f"[BootLogon] Sample registry keys for events: {registry_key_col[:3]} ...")
        value_name_col = [rng.choice(value_names) for _ in range(n)]
        exe_name_col = [rng.choice(exe_names) for _ in range(n)]
        value_data_col = [rng.choice(value_data_templates).format(
                account_name=victims_df["AccountName"][i] if "AccountName" in victims_df.columns else "user",
                exe=exe_name_col[i]
        ) for i in range(n)]
        base_time = self.config.last_scan_time if isinstance(self.config.last_scan_time, datetime) else datetime.fromisoformat(self.config.last_scan_time)
        timestamp_col = [base_time + timedelta(minutes=rng.randint(-10, 10)) for _ in range(n)]

        # Faker/random fields
        sha1_col = [fake.sha1() for _ in range(n)]
        sha256_col = [fake.sha256() for _ in range(n)]
        md5_col = [fake.md5() for _ in range(n)]
        file_size_col = [rng.randint(100, 10_000_000) for _ in range(n)]
        company_col = [fake.company() for _ in range(n)]
        product_name_col = [fake.word() for _ in range(n)]
        product_version_col = [f"{rng.randint(1, 10)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}" for _ in range(n)]
        file_desc_col = [fake.sentence() for _ in range(n)]
        proc_id_col = [rng.randint(1000, 9999) for _ in range(n)]
        cmdline_col = [f"{exe_name_col[i]} --run" for i in range(n)]
        proc_create_time_col = [timestamp_col[i] - timedelta(seconds=rng.randint(10, 300)) for i in range(n)]
        folder_path_col = [f"C:\\Users\\{victims_df['AccountName'][i] if 'AccountName' in victims_df.columns else 'user'}\\AppData\\Local\\Temp" for i in range(n)]
        parent_id_col = [rng.randint(1000, 9999) for _ in range(n)]
        parent_file_col = [fake.file_name() for _ in range(n)]
        parent_create_time_col = [timestamp_col[i] - timedelta(minutes=rng.randint(1, 60)) for i in range(n)]
        integrity_col = [rng.choice(["Low", "Medium", "High"]) for _ in range(n)]
        token_elev_col = [rng.choice(["TokenElevationTypeLimited", "TokenElevationTypeDefault", "TokenElevationTypeFull"]) for _ in range(n)]
        report_id_col = [rng.randint(100000, 999999) for _ in range(n)]
        appguard_col = [str(uuid4()) for _ in range(n)]
        session_id_col = [rng.randint(1, 10) for _ in range(n)]
        is_remote_col = [rng.choice([True, False]) for _ in range(n)]
        remote_name_col = [fake.hostname() for _ in range(n)]
        remote_ip_col = [fake.ipv4() for _ in range(n)]

        # Build the column map for the schema fields
        manual_overrides = {
            "ActionType": [action_type] * n,
            "RegistryValueType": [registry_value_type] * n,
        }
        events_df = self.build_events_df(DeviceRegistryEvents, n, victims_df, manual_overrides)

        # --- Fix DataFrame warnings ---
        # Ensure RegistryKey is string
        if "RegistryKey" in events_df.columns:
            events_df = events_df.with_columns(pl.col("RegistryKey").cast(pl.String))
        # Drop rows with null DeviceId
        if "DeviceId" in events_df.columns:
            events_df = events_df.filter(pl.col("DeviceId").is_not_null())
        # Ensure ExeName exists and is string
        if "ExeName" not in events_df.columns:
            events_df = events_df.with_columns([pl.lit("").alias("ExeName")])
        else:
            events_df = events_df.with_columns(pl.col("ExeName").cast(pl.String))
        # --- End fix ---

        if self.debug:
            self.log_info(f"[BootLogon] Events DataFrame shape: {events_df.shape}")

        self.data = {"device_registry_events": events_df}
        if self.debug:
            self.log_info("[BootLogon] Attack generation complete.")
        updated_victims = self.config.victims
        last_event_time = events_df["Timestamp"].max() if events_df.height > 0 else self.config.last_scan_time
        return self.data, updated_victims, last_event_time 

    def answer_persistence_established(self, tables=None):
        """Was persistence established via registry run keys?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None:
                return "Yes"
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_persistence_established: {e}", exc_info=True)
            return None

    def answer_most_common_registry_key(self, tables=None):
        """Which registry key was most commonly used for persistence?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None and self._check_column(df, "RegistryKey", pl.String):
                return self._most_common_value(df, "RegistryKey")
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_most_common_registry_key: {e}", exc_info=True)
            return None

    def answer_unique_devices_modified(self, tables=None):
        """How many unique devices modified registry run keys during the attack?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None and self._check_column(df, "DeviceId"):
                return self._unique_count(df, "DeviceId")
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_unique_devices_modified: {e}", exc_info=True)
            return None

    def answer_most_common_process(self, tables=None):
        """What was the most common process used to modify registry run keys?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None and self._check_column(df, "ExeName", pl.String):
                return self._most_common_value(df, "ExeName")
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_most_common_process: {e}", exc_info=True)
            return None

    def answer_most_active_user(self, tables=None):
        """Which user account performed the most registry modifications during the attack?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None and self._check_column(df, "InitiatingProcessAccountName"):
                return self._most_common_value(df, "InitiatingProcessAccountName")
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_most_active_user: {e}", exc_info=True)
            return None

    def answer_registry_modification_timeframe(self, tables=None):
        """What was the time frame between the first and last registry modification during the attack?"""
        if tables is None:
            tables = self.data
        try:
            df = self._get_table(tables, "device_registry_events")
            if df is not None and self._check_column(df, "Timestamp"):
                return self._time_frame(df, "Timestamp")
            return None
        except Exception as e:
            self.log_error(f"Exception in answer_registry_modification_timeframe: {e}", exc_info=True)
            return None 