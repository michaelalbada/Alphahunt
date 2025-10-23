"""Pydantic models for device process events."""

from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime

class DeviceProcessEvents(BaseModel):
    """Model for device process events."""
    
    Timestamp: datetime
    DeviceId: str
    DeviceName: str
    ActionType: str
    FileName: str
    FolderPath: str
    ProcessCommandLine: str
    ProcessIntegrityLevel: str
    ProcessTokenElevation: str
    AccountDomain: str
    AccountName: str
    AccountSid: str
    InitiatingProcessFileName: str
    InitiatingProcessCommandLine: str
    InitiatingProcessFolderPath: str
    SHA1: Optional[str] = None
    MD5: Optional[str] = None
    ProcessId: Optional[int] = None
    ProcessCreationTime: Optional[datetime] = None
    InitiatingProcessId: Optional[int] = None
    InitiatingProcessCreationTime: Optional[datetime] = None
    InitiatingProcessSHA1: Optional[str] = None
    InitiatingProcessMD5: Optional[str] = None
    AdditionalFields: Optional[Dict[str, Any]] = None

    @field_validator('DeviceId', 'DeviceName', 'ActionType')
    def validate_required_strings(cls, v: str) -> str:
        if not v:
            raise ValueError("Field cannot be empty")
        return v

    @model_validator(mode="after")
    def validate_process_info(self) -> 'DeviceProcessEvents':
        """Validate process-related information."""
        if self.ProcessId is not None and self.ProcessId <= 0:
            raise ValueError("ProcessId must be positive")
        if self.InitiatingProcessId is not None and self.InitiatingProcessId <= 0:
            raise ValueError("InitiatingProcessId must be positive")
        return self 