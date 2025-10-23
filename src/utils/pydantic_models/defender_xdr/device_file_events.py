from typing import Optional
from pydantic import BaseModel, field_validator, model_validator
from datetime import datetime

class DeviceFileEvents(BaseModel):
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
    ProcessId: Optional[int] = None
    ProcessCommandLine: Optional[str] = None
    InitiatingProcessAccountDomain: Optional[str] = None
    InitiatingProcessAccountName: Optional[str] = None
    InitiatingProcessAccountSid: Optional[str] = None
    InitiatingProcessSHA1: Optional[str] = None
    InitiatingProcessSHA256: Optional[str] = None
    InitiatingProcessMD5: Optional[str] = None
    InitiatingProcessFileName: Optional[str] = None
    InitiatingProcessId: Optional[int] = None
    InitiatingProcessCommandLine: Optional[str] = None
    InitiatingProcessCreationTime: Optional[datetime] = None
    ReportId: Optional[int] = None
    AdditionalFields: Optional[str] = None

    @field_validator('DeviceId', 'DeviceName', 'ActionType')
    @classmethod
    def not_empty(cls, v):
        if not v or not str(v).strip():
            raise ValueError("Field must not be empty")
        return v

    @model_validator(mode="after")
    def check_required_fields(self):
        if not (self.FileName or self.ProcessCommandLine):
            raise ValueError("At least one of FileName or ProcessCommandLine must be present.")
        return self 