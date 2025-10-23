from typing import Optional
from pydantic import BaseModel, field_validator, model_validator
from datetime import datetime

class DeviceEvents(BaseModel):
    Timestamp: datetime
    DeviceId: str
    DeviceName: str
    ActionType: str
    FileName: Optional[str] = None
    FolderPath: Optional[str] = None
    SHA1: Optional[str] = None
    SHA256: Optional[str] = None
    MD5: Optional[str] = None
    FileSize: Optional[int] = None
    AccountDomain: Optional[str] = None
    AccountName: Optional[str] = None
    AccountSid: Optional[str] = None
    RemoteUrl: Optional[str] = None
    RemoteDeviceName: Optional[str] = None
    ProcessId: Optional[int] = None
    ProcessCommandLine: Optional[str] = None
    ProcessCreationTime: Optional[datetime] = None
    ProcessTokenElevation: Optional[str] = None
    LogonId: Optional[int] = None
    RegistryKey: Optional[str] = None
    RegistryValueName: Optional[str] = None
    RegistryValueData: Optional[str] = None
    RemoteIP: Optional[str] = None
    RemotePort: Optional[int] = None
    LocalIP: Optional[str] = None
    LocalPort: Optional[int] = None
    FileOriginUrl: Optional[str] = None
    FileOriginIP: Optional[str] = None
    InitiatingProcessSHA1: Optional[str] = None
    InitiatingProcessSHA256: Optional[str] = None
    InitiatingProcessMD5: Optional[str] = None
    InitiatingProcessFileName: Optional[str] = None
    InitiatingProcessFileSize: Optional[int] = None
    InitiatingProcessFolderPath: Optional[str] = None
    InitiatingProcessId: Optional[int] = None
    InitiatingProcessCommandLine: Optional[str] = None
    InitiatingProcessCreationTime: Optional[datetime] = None
    InitiatingProcessAccountDomain: Optional[str] = None
    InitiatingProcessAccountName: Optional[str] = None
    InitiatingProcessAccountSid: Optional[str] = None
    InitiatingProcessAccountUpn: Optional[str] = None
    InitiatingProcessAccountObjectId: Optional[str] = None
    InitiatingProcessVersionInfoCompanyName: Optional[str] = None
    InitiatingProcessVersionInfoProductName: Optional[str] = None
    InitiatingProcessVersionInfoProductVersion: Optional[str] = None
    InitiatingProcessVersionInfoInternalFileName: Optional[str] = None
    InitiatingProcessVersionInfoOriginalFileName: Optional[str] = None
    InitiatingProcessVersionInfoFileDescription: Optional[str] = None
    InitiatingProcessParentId: Optional[int] = None
    InitiatingProcessParentFileName: Optional[str] = None
    InitiatingProcessParentCreationTime: Optional[datetime] = None
    InitiatingProcessLogonId: Optional[int] = None
    ReportId: Optional[int] = None
    AppGuardContainerId: Optional[str] = None
    AdditionalFields: Optional[str] = None
    InitiatingProcessSessionId: Optional[int] = None
    IsInitiatingProcessRemoteSession: Optional[bool] = None
    InitiatingProcessRemoteSessionDeviceName: Optional[str] = None
    InitiatingProcessRemoteSessionIP: Optional[str] = None
    CreatedProcessSessionId: Optional[int] = None
    IsProcessRemoteSession: Optional[bool] = None
    ProcessRemoteSessionDeviceName: Optional[str] = None
    ProcessRemoteSessionIP: Optional[str] = None
    ProcessUniqueId: Optional[str] = None
    InitiatingProcessUniqueId: Optional[str] = None

    @field_validator('DeviceId', 'DeviceName', 'ActionType')
    @classmethod
    def not_empty(cls, v):
        if not v or not str(v).strip():
            raise ValueError("Field must not be empty")
        return v

    @model_validator(mode="after")
    def check_required_fields(self):
        if not (self.FileName or self.ProcessCommandLine or self.RegistryKey):
            raise ValueError("At least one of FileName, ProcessCommandLine, or RegistryKey must be present.")
        return self 