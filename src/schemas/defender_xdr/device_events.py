from sqlalchemy import Column, BigInteger, Integer, String, Boolean, DateTime, Text
from src.data_generation.defender_xdr.base import Base
  
class DeviceEvents(Base):
    __tablename__ = 'DeviceEvents'  

    Timestamp = Column(  
        DateTime,  
        nullable=False,  
        comment="Date and time when the event was recorded"  
    )  
    DeviceId = Column(  
        String(50),  
        nullable=False,  
        comment="Unique identifier for the device in the service"  
    )  
    DeviceName = Column(  
        Text,  
        comment="Fully qualified domain name (FQDN) of the device"  
    )  
    ActionType = Column(  
        Text,  
        comment="Type of activity that triggered the event. See the in-portal schema reference for details."  
    )  
    FileName = Column(  
        Text,  
        comment="Name of the file that the recorded action was applied to"  
    )  
    FolderPath = Column(  
        String(1024),  
        comment="Folder containing the file that the recorded action was applied to"  
    )  
    SHA1 = Column(  
        String(40),  
        comment="SHA-1 of the file that the recorded action was applied to"  
    )  
    SHA256 = Column(  
        String(64),  
        comment="SHA-256 of the file that the recorded action was applied to. This field is usually not populated — use the SHA1 column when available."  
    )  
    MD5 = Column(  
        String(32),  
        comment="MD5 hash of the file that the recorded action was applied to"  
    )  
    FileSize = Column(  
        BigInteger,  
        comment="Size of the file in bytes"  
    )  
    AccountDomain = Column(  
        Text,  
        comment="Domain of the account"  
    )  
    AccountName = Column(  
        Text,  
        comment="User name of the account; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account might be shown instead"  
    )  
    AccountSid = Column(  
        Text,  
        comment="Security Identifier (SID) of the account"  
    )  
    RemoteUrl = Column(  
        String(2048),  
        comment="URL or fully qualified domain name (FQDN) that was being connected to"  
    )  
    RemoteDeviceName = Column(  
        Text,  
        comment="Name of the device that performed a remote operation on the affected device. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information."  
    )  
    ProcessId = Column(  
        BigInteger,  
        comment="Process ID (PID) of the newly created process"  
    )  
    ProcessCommandLine = Column(  
        String(1024),  
        comment="Command line used to create the new process"  
    )  
    ProcessCreationTime = Column(  
        DateTime,  
        comment="Date and time the process was created"  
    )  
    ProcessTokenElevation = Column(  
        String(50),  
        comment="Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated)"  
    )  
    LogonId = Column(  
        BigInteger,  
        comment="Identifier for a logon session. This identifier is unique on the same device only between restarts."  
    )  
    RegistryKey = Column(  
        String(1024),  
        comment="Registry key that the recorded action was applied to"  
    )  
    RegistryValueName = Column(  
        Text,  
        comment="Name of the registry value that the recorded action was applied to"  
    )  
    RegistryValueData = Column(  
        String(512),  
        comment="Data of the registry value that the recorded action was applied to"  
    )  
    RemoteIP = Column(  
        String(45),  
        comment="IP address that was being connected to"  
    )  
    RemotePort = Column(  
        Integer,  
        comment="TCP port on the remote device that was being connected to"  
    )  
    LocalIP = Column(  
        String(45),  
        comment="IP address assigned to the local device used during communication"  
    )  
    LocalPort = Column(  
        Integer,  
        comment="TCP port on the local device used during communication"  
    )  
    FileOriginUrl = Column(  
        String(2083),  
        comment="URL where the file was downloaded from"  
    )  
    FileOriginIP = Column(  
        String(45),  
        comment="IP address where the file was downloaded from"  
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
        Text,  
        comment="Name of the process file that initiated the event; if unavailable, the name of the process that initiated the event might be shown instead"  
    )  
    InitiatingProcessFileSize = Column(  
        BigInteger,  
        comment="Size of the file that ran the process responsible for the event"  
    )  
    InitiatingProcessFolderPath = Column(  
        String(1024),  
        comment="Folder containing the process (image file) that initiated the event"  
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
    InitiatingProcessAccountDomain = Column(  
        Text,  
        comment="Domain of the account that ran the process responsible for the event"  
    )  
    InitiatingProcessAccountName = Column(  
        Text,  
        comment="User name of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID user name of the account that ran the process responsible for the event might be shown instead"  
    )  
    InitiatingProcessAccountSid = Column(  
        Text,  
        comment="Security Identifier (SID) of the account that ran the process responsible for the event"  
    )  
    InitiatingProcessAccountUpn = Column(  
        Text,  
        comment="User principal name (UPN) of the account that ran the process responsible for the event; if the device is registered in Microsoft Entra ID, the Entra ID UPN of the account that ran the process responsible for the event might be shown instead"  
    )  
    InitiatingProcessAccountObjectId = Column(  
        Text,  
        comment="Microsoft Entra object ID of the user account that ran the process responsible for the event"  
    )  
    InitiatingProcessVersionInfoCompanyName = Column(  
        Text,  
        comment="Company name from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessVersionInfoProductName = Column(  
        Text,  
        comment="Product name from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessVersionInfoProductVersion = Column(  
        Text,  
        comment="Product version from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessVersionInfoInternalFileName = Column(  
        Text,  
        comment="Internal file name from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessVersionInfoOriginalFileName = Column(  
        Text,  
        comment="Original file name from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessVersionInfoFileDescription = Column(  
        Text,  
        comment="Description from the version information of the process (image file) responsible for the event"  
    )  
    InitiatingProcessParentId = Column(  
        BigInteger,  
        comment="Process ID (PID) of the parent process that spawned the process responsible for the event"  
    )  
    InitiatingProcessParentFileName = Column(  
        Text,  
        comment="Name or full path of the parent process that spawned the process responsible for the event"  
    )  
    InitiatingProcessParentCreationTime = Column(  
        DateTime,  
        comment="Date and time when the parent of the process responsible for the event was started"  
    )  
    InitiatingProcessLogonId = Column(  
        BigInteger,  
        comment="Identifier for a logon session of the process that initiated the event. This identifier is unique on the same device only between restarts."  
    )  
    ReportId = Column(  
        BigInteger,  
        primary_key=True,  
        comment="Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns."  
    )  
    AppGuardContainerId = Column(  
        Text,  
        comment="Identifier for the virtualized container used by Application Guard to isolate browser activity"  
    )  
    AdditionalFields = Column(  
        Text,  
        comment="Additional information about the event in JSON array format"  
    )  
    InitiatingProcessSessionId = Column(  
        Integer,  
        comment="Windows session ID of the initiating process"  
    )  
    IsInitiatingProcessRemoteSession = Column(  
        Boolean,  
        comment="Indicates whether the initiating process was run under a remote desktop protocol (RDP) session (true) or locally (false)"  
    )  
    InitiatingProcessRemoteSessionDeviceName = Column(  
        Text,  
        comment="Device name of the remote device from which the initiating process’s RDP session was initiated"  
    )  
    InitiatingProcessRemoteSessionIP = Column(  
        String(45),  
        comment="IP address of the remote device from which the initiating process’s RDP session was initiated"  
    )  
    CreatedProcessSessionId = Column(  
        Integer,  
        comment="Windows session ID of the created process"  
    )  
    IsProcessRemoteSession = Column(  
        Boolean,  
        comment="Indicates whether the created process was run under a remote desktop protocol (RDP) session (true) or locally (false)"  
    )  
    ProcessRemoteSessionDeviceName = Column(  
        Text,  
        comment="Device name of the remote device from which the created process’s RDP session was initiated"  
    )  
    ProcessRemoteSessionIP = Column(  
        String(45),  
        comment="IP address of the remote device from which the created process’s RDP session was initiated"  
    )