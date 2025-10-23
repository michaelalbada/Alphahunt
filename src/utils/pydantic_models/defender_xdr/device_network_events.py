"""Pydantic models for device network events."""

from typing import Optional, Dict, Any
from pydantic import BaseModel, field_validator, model_validator
from datetime import datetime, timedelta
from faker import Faker
import random
import hashlib

class DeviceNetworkEvents(BaseModel):
    """Model for device network events."""
    
    Timestamp: datetime
    DeviceId: str
    DeviceName: str
    ActionType: str
    Protocol: str
    LocalPort: int
    RemotePort: int
    LocalIP: str
    RemoteIP: str
    RemoteUrl: Optional[str] = None
    InitiatingProcessFileName: str
    InitiatingProcessCommandLine: str
    BytesSent: int
    BytesReceived: int
    InitiatingProcessFolderPath: str
    AdditionalFields: Optional[Dict[str, Any]] = None
    
    # Network connection details
    LocalIPType: Optional[str] = None  # Type of IP address (Public, Private, Reserved, etc.)
    RemoteIPType: Optional[str] = None  # Type of IP address (Public, Private, Reserved, etc.)
    
    # Process hashes
    InitiatingProcessSHA1: Optional[str] = None  # SHA-1 of the process that initiated the event
    InitiatingProcessSHA256: Optional[str] = None  # SHA-256 of the process that initiated the event
    InitiatingProcessMD5: Optional[str] = None  # MD5 hash of the process that initiated the event
    
    # Process details
    InitiatingProcessFileSize: Optional[int] = None  # Size of the file that ran the process
    InitiatingProcessVersionInfoCompanyName: Optional[str] = None  # Company name from version info
    InitiatingProcessVersionInfoProductName: Optional[str] = None  # Product name from version info
    InitiatingProcessVersionInfoProductVersion: Optional[str] = None  # Product version from version info
    InitiatingProcessVersionInfoInternalFileName: Optional[str] = None  # Internal file name from version info
    InitiatingProcessVersionInfoOriginalFileName: Optional[str] = None  # Original file name from version info
    InitiatingProcessVersionInfoFileDescription: Optional[str] = None  # Description from version info
    InitiatingProcessId: Optional[int] = None  # Process ID (PID) of the process
    InitiatingProcessCreationTime: Optional[datetime] = None  # Date and time when the process was started
    InitiatingProcessParentFileName: Optional[str] = None  # Name of the parent process
    InitiatingProcessParentId: Optional[int] = None  # Process ID (PID) of the parent process
    InitiatingProcessParentCreationTime: Optional[datetime] = None  # Start time of parent process
    
    # Account information
    InitiatingProcessAccountDomain: Optional[str] = None  # Domain of the account
    InitiatingProcessAccountName: Optional[str] = None  # User name of the account
    InitiatingProcessAccountSid: Optional[str] = None  # Security Identifier (SID) of the account
    InitiatingProcessAccountUpn: Optional[str] = None  # User principal name (UPN) of the account
    InitiatingProcessAccountObjectId: Optional[str] = None  # Microsoft Entra object ID
    InitiatingProcessIntegrityLevel: Optional[str] = None  # Integrity level of the process
    InitiatingProcessTokenElevation: Optional[str] = None  # UAC privilege elevation type
    
    # Additional information
    ReportId: Optional[int] = None  # Event identifier based on a repeating counter
    AppGuardContainerId: Optional[str] = None  # Identifier for virtualized container
    
    # Remote session information
    InitiatingProcessSessionId: Optional[int] = None  # Windows session ID
    IsInitiatingProcessRemoteSession: Optional[bool] = None  # Whether process was run under RDP
    InitiatingProcessRemoteSessionDeviceName: Optional[str] = None  # Remote RDP device name
    InitiatingProcessRemoteSessionIP: Optional[str] = None  # Remote RDP IP address
    
    # Process unique identifiers
    ProcessUniqueId: Optional[str] = None  # Unique identifier of the process
    InitiatingProcessUniqueId: Optional[str] = None  # Unique identifier of initiating process
    
    @field_validator('DeviceId', 'DeviceName', 'ActionType', 'Protocol', 'LocalIP', 'RemoteIP')
    def validate_required_strings(cls, v: str) -> str:
        if not v:
            raise ValueError("Field cannot be empty")
        return v
    
    @field_validator('LocalPort', 'RemotePort', 'BytesSent', 'BytesReceived')
    def validate_positive_integers(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Value must be positive")
        return v
    
    @model_validator(mode="after")
    def check_required_fields(self):
        """Validate that required combinations of fields are present."""
        # Network events must have valid IP addresses and ports
        if not all([self.Protocol, self.LocalIP, self.RemoteIP, self.LocalPort, self.RemotePort]):
            raise ValueError("Network events must have Protocol, LocalIP, RemoteIP, LocalPort, and RemotePort")
            
        # If we have process info, we should have the basic process fields
        if self.InitiatingProcessId and not self.InitiatingProcessCommandLine:
            raise ValueError("If InitiatingProcessId is present, InitiatingProcessCommandLine must also be present")
            
        return self 

    @classmethod
    def generate_instance(
        cls,
        identity_row,
        device_row,
        timestamp,
        fake,
        process_name=None,
        destination_ip=None,
        destination_port=None,
        protocol=None,
        url=None,
        user_agent=None,
        http_headers=None,
        **overrides
    ):
        PROCESS_NAMES = [
            'explorer.exe', 'cmd.exe', 'powershell.exe', 'python.exe', 'notepad.exe', 'svchost.exe'
        ]
        additional_fields = {
            "UserAgent": user_agent if user_agent else fake.user_agent(),
            "HttpHeaders": http_headers if http_headers else {}
        }
        data = dict(
            Timestamp=timestamp,
            DeviceId=device_row["DeviceId"],
            DeviceName=device_row["DeviceName"],
            ActionType="NetworkConnection",
            RemoteIP=destination_ip if destination_ip else fake.ipv4(),
            RemotePort=destination_port if destination_port else random.randint(1024, 65535),
            RemoteUrl=url if url else fake.url(),
            LocalIP=device_row.get("PublicIP", fake.ipv4()),
            LocalPort=random.randint(49152, 65535),
            Protocol=protocol if protocol else random.choice(["TCP", "UDP"]),
            LocalIPType="Public",
            RemoteIPType="Public",
            InitiatingProcessSHA1=hashlib.sha1(fake.file_name().encode()).hexdigest(),
            InitiatingProcessSHA256=hashlib.sha256(fake.file_name().encode()).hexdigest(),
            InitiatingProcessMD5=hashlib.md5(fake.file_name().encode()).hexdigest(),
            InitiatingProcessFileName=process_name if process_name else random.choice(PROCESS_NAMES),
            InitiatingProcessFileSize=random.randint(100, 10_000_000),
            InitiatingProcessVersionInfoCompanyName=fake.company(),
            InitiatingProcessVersionInfoProductName=fake.word(),
            InitiatingProcessVersionInfoProductVersion=f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
            InitiatingProcessVersionInfoInternalFileName=fake.file_name(),
            InitiatingProcessVersionInfoOriginalFileName=fake.file_name(),
            InitiatingProcessVersionInfoFileDescription=fake.sentence(),
            InitiatingProcessId=random.randint(1000, 9999),
            InitiatingProcessCommandLine=f"{random.choice(PROCESS_NAMES)} {fake.file_path(depth=2)}",
            InitiatingProcessCreationTime=fake.date_time_between(start_date=timestamp - timedelta(days=1), end_date=timestamp),
            InitiatingProcessFolderPath=fake.file_path(depth=3),
            InitiatingProcessParentId=random.randint(1000, 9999),
            InitiatingProcessParentFileName=fake.file_name(),
            InitiatingProcessParentCreationTime=fake.date_time_between(start_date=timestamp - timedelta(days=1), end_date=timestamp),
            InitiatingProcessAccountDomain=identity_row["AccountDomain"],
            InitiatingProcessAccountName=identity_row["AccountName"],
            InitiatingProcessAccountSid=identity_row["OnPremSid"],
            InitiatingProcessAccountUpn=identity_row["AccountUpn"],
            InitiatingProcessAccountObjectId=identity_row["AccountObjectId"],
            InitiatingProcessIntegrityLevel=random.choice(["Medium", "High"]),
            InitiatingProcessTokenElevation=random.choice(["TokenElevationTypeLimited", "TokenElevationTypeDefault", "TokenElevationTypeFull"]),
            ReportId=fake.uuid4(),
            AppGuardContainerId="",
            AdditionalFields=additional_fields,
            InitiatingProcessSessionId=random.randint(1000, 9999),
            IsInitiatingProcessRemoteSession=random.choice([True, False]),
            InitiatingProcessRemoteSessionDeviceName=fake.hostname() if random.choice([True, False]) else "",
            InitiatingProcessRemoteSessionIP=fake.ipv4() if random.choice([True, False]) else ""
        )
        data.update(overrides)
        return cls(**data) 