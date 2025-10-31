from sqlalchemy import Column, Integer, BigInteger, String, DateTime, Boolean  
from .base import Base

class DeviceRegistryEvents(Base):
    __tablename__ = 'DeviceRegistryEvents'

    id = Column(
        Integer,
        primary_key=True,
        autoincrement=True  
    )

    Timestamp = Column(
        DateTime,
        nullable=False,
        comment="Date and time when the event was recorded"  
    )

    DeviceId = Column(
        String(255),
        comment="Unique identifier for the device in the service"  
    )

    DeviceName = Column(
        String(255),
        comment="Fully qualified domain name (FQDN) of the device"  
    )

    ActionType = Column(
        String(100),
        comment="Type of activity that triggered the event"  
    )

    RegistryKey = Column(
        String(1024),
        comment="Registry key that the recorded action was applied to"  
    )

    RegistryValueType = Column(
        String(50),
        comment="Data type, such as binary or string, of the registry value that the recorded action was applied to"  
    )

    RegistryValueName = Column(
        String(255),
        comment="Name of the registry value that the recorded action was applied to"  
    )

    RegistryValueData = Column(
        String(1024),
        comment="Data of the registry value that the recorded action was applied to"  
    )

    PreviousRegistryKey = Column(
        String(1024),
        comment="Original registry key of the registry value before it was modified"  
    )

    PreviousRegistryValueName = Column(
        String(255),
        comment="Original name of the registry value before it was modified"  
    )

    PreviousRegistryValueData = Column(
        String(1024),
        comment="Original data of the registry value before it was modified"  
    )

    InitiatingProcessAccountDomain = Column(
        String(255),
        comment="Domain of the account that ran the process responsible for the event"  
    )

    InitiatingProcessAccountName = Column(
        String(255),
        comment="User name of the account that ran the process responsible for the event"  
    )

    InitiatingProcessAccountSid = Column(
        String(128),
        comment="Security Identifier (SID) of the account that ran the process responsible for the event"  
    )

    InitiatingProcessAccountUpn = Column(
        String(255),
        comment="User principal name (UPN) of the account that ran the process responsible for the event"  
    )

    InitiatingProcessAccountObjectId = Column(
        String(255),
        comment="Microsoft Entra object ID of the user account that ran the process responsible for the event"  
    )

    InitiatingProcessSHA1 = Column(
        String(40),
        comment="SHA-1 of the process (image file) that initiated the event"  
    )

    InitiatingProcessSHA256 = Column(
        String(64),
        comment="SHA-256 of the process (image file) that initiated the event. This field is usually not populated — use the SHA1 column when available."  
    )

    InitiatingProcessMD5 = Column(
        String(32),
        comment="MD5 hash of the process (image file) that initiated the event"  
    )

    InitiatingProcessFileName = Column(
        String(255),
        comment="Name of the process file that initiated the event"  
    )

    InitiatingProcessFileSize = Column(
        BigInteger,
        comment="Size of the file that ran the process responsible for the event"  
    )

    InitiatingProcessVersionInfoCompanyName = Column(
        String(255),
        comment="Company name from the version information of the process (image file) responsible for the event"  
    )

    InitiatingProcessVersionInfoProductName = Column(
        String(255),
        comment="Product name from the version information of the process (image file) responsible for the event"  
    )
  
    InitiatingProcessVersionInfoProductVersion = Column(
        String(255),
        comment="Product version from the version information of the process (image file) responsible for the event"  
    )

    InitiatingProcessVersionInfoInternalFileName = Column(
        String(255),
        comment="Internal file name from the version information of the process (image file) responsible for the event"  
    )

    InitiatingProcessVersionInfoOriginalFileName = Column(
        String(255),
        comment="Original file name from the version information of the process (image file) responsible for the event"  
    )

    InitiatingProcessVersionInfoFileDescription = Column(
        String(255),
        comment="Description from the version information of the process (image file) responsible for the event"  
    )
  
    InitiatingProcessId = Column(
        BigInteger,
        comment="Process ID (PID) of the process that initiated the event"  
    )

    InitiatingProcessCommandLine = Column(
        String(2048),
        comment="Command line used to run the process that initiated the event"  
    )

    InitiatingProcessCreationTime = Column(
        DateTime,
        comment="Date and time when the process that initiated the event was started"  
    )

    InitiatingProcessFolderPath = Column(
        String(1024),
        comment="Folder containing the process (image file) that initiated the event"  
    )

    InitiatingProcessParentId = Column(
        BigInteger,
        comment="Process ID (PID) of the parent process that spawned the process responsible for the event"  
    )

    InitiatingProcessParentFileName = Column(
        String(255),
        comment="Name of the parent process that spawned the process responsible for the event"  
    )

    InitiatingProcessParentCreationTime = Column(
        DateTime,
        comment="Date and time when the parent of the process responsible for the event was started"  
    )

    InitiatingProcessIntegrityLevel = Column(
        String(50),
        comment="Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources."  
    )

    InitiatingProcessTokenElevation = Column(
        String(50),
        comment="Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event"  
    )

    ReportId = Column(
        BigInteger,
        comment="Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns."  
    )

    AppGuardContainerId = Column(
        String(255),
        comment="Identifier for the virtualized container used by Application Guard to isolate browser activity"  
    )

    InitiatingProcessSessionId = Column(
        BigInteger,
        comment="Windows session ID of the initiating process"  
    )

    IsInitiatingProcessRemoteSession = Column(
        Boolean,
        comment="Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)"  
    )

    InitiatingProcessRemoteSessionDeviceName = Column(
        String(255),
        comment="Device name of the remote device from which the initiating process's RDP session was initiated"  
    )

    InitiatingProcessRemoteSessionIP = Column(
        String(45),
        comment="IP address of the remote device from which the initiating process's RDP session was initiated"  
    )
