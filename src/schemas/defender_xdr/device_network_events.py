from sqlalchemy import Column, Integer, BigInteger, String, Boolean, DateTime, Text
from src.data_generation.defender_xdr.base import Base  
  
class DeviceNetworkEvents(Base):  
    __tablename__ = 'DeviceNetworkEvents'  
  
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
        String(64),  
        comment="Unique identifier for the device in the service"  
    )  
    DeviceName = Column(  
        String(255),  
        comment="Fully qualified domain name (FQDN) of the device"  
    )  
    ActionType = Column(  
        String(50),  
        comment="Type of activity that triggered the event. See the in-portal schema reference for details."  
    )  
    RemoteIP = Column(  
        String(45),  
        comment="IP address that was being connected to"  
    )  
    RemotePort = Column(  
        Integer,  
        comment="TCP port on the remote device that was being connected to"  
    )  
    RemoteUrl = Column(  
        String(1024),  
        comment="URL or fully qualified domain name (FQDN) that was being connected to"  
    )  
    LocalIP = Column(  
        String(45),  
        comment="Source IP, or the IP address where the communication came from"  
    )  
    LocalPort = Column(  
        Integer,  
        comment="TCP port on the local device used during communication"  
    )  
    Protocol = Column(  
        String(50),  
        comment="Protocol used during the communication"  
    )  
    LocalIPType = Column(  
        String(50),  
        comment="Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast"  
    )  
    RemoteIPType = Column(  
        String(50),  
        comment="Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast"  
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
        String(1024),  
        comment="Command line used to run the process that initiated the event"  
    )  
    InitiatingProcessCreationTime = Column(  
        DateTime,  
        comment="Date and time when the process that initiated the event was started"  
    )  
    InitiatingProcessFolderPath = Column(  
        String(512),  
        comment="Folder containing the process (image file) that initiated the event"  
    )  
    InitiatingProcessParentFileName = Column(  
        String(255),  
        comment="Name of the parent process that spawned the process responsible for the event"  
    )  
    InitiatingProcessParentId = Column(  
        BigInteger,  
        comment="Process ID (PID) of the parent process that spawned the process responsible for the event"  
    )  
    InitiatingProcessParentCreationTime = Column(  
        DateTime,  
        comment="Date and time when the parent of the process responsible for the event was started"  
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
        String(36),  
        comment="Microsoft Entra object ID of the user account that ran the process responsible for the event"  
    )  
    InitiatingProcessIntegrityLevel = Column(  
        String(50),  
        comment="Integrity level of the process that initiated the event."  
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
    AdditionalFields = Column(  
        Text,  
        comment="Additional information about the event in JSON array format"  
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
        comment="Device name of the remote device from which the initiating process’s RDP session was initiated"  
    )  
    InitiatingProcessRemoteSessionIP = Column(  
        String(45),  
        comment="IP address of the remote device from which the initiating process’s RDP session was initiated"  
    )
