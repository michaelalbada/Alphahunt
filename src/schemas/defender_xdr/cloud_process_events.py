from sqlalchemy import Column, Integer, BigInteger, String, DateTime  
from .base import Base

class CloudProcessEvents(Base):  
    __tablename__ = 'CloudProcessEvents'  

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
    AzureResourceId = Column(  
        String(255),  
        comment="Unique identifier of the Azure resource associated with the process"  
    )
    AwsResourceName = Column(  
        String(255),  
        comment="Unique identifier specific to Amazon Web Services devices, containing the Amazon resource name"  
    )
    GcpFullResourceName = Column(  
        String(255),  
        comment="Unique identifier specific to Google Cloud Platform devices, containing a combination of zone and ID for GCP"  
    )
    ContainerImageName = Column(  
        String(255),  
        comment="The container image name or ID, if it exists"  
    )
    KubernetesNamespace = Column(  
        String(255),  
        comment="The Kubernetes namespace name"  
    )
    KubernetesPodName = Column(  
        String(255),  
        comment="The Kubernetes pod name"  
    )
    KubernetesResource = Column(  
        String(255),  
        comment="Identifier value that includes namespace, resource type and name"  
    )
    ContainerName = Column(  
        String(255),  
        comment="Name of the container in Kubernetes or another runtime environment"  
    )
    ContainerId = Column(  
        String(255),  
        comment="The container identifier in Kubernetes or another runtime environment"  
    )
    ActionType = Column(  
        String(50),  
        comment="Type of activity that triggered the event. See the in-portal schema reference for details."  
    )
    FileName = Column(  
        String(255),  
        comment="Name of the file that the recorded action was applied to"  
    )
    FolderPath = Column(  
        String(512),  
        comment="Folder containing the file that the recorded action was applied to"  
    )
    ProcessId = Column(  
        BigInteger,  
        comment="Process ID (PID) of the newly created process"  
    )
    ProcessName = Column(  
        String(255),  
        comment="The name of the process"  
    )
    ParentProcessName = Column(  
        String(255),  
        comment="The name of the parent process"  
    )
    ParentProcessId = Column(  
        String(255),  
        comment="The process ID (PID) of the parent process"  
    )
    ProcessCommandLine = Column(  
        String(1024),  
        comment="Command line used to create the new process"  
    )
    ProcessCreationTime = Column(  
        DateTime,  
        comment="Date and time the process was created"  
    )
    ProcessCurrentWorkingDirectory = Column(  
        String(512),  
        comment="Current working directory of the running process"  
    )
    AccountName = Column(  
        String(255),  
        comment="User name of the account"  
    )
    LogonId = Column(  
        BigInteger,  
        comment="Identifier for a logon session. This identifier is unique on the same pod or container between restarts."  
    )
    InitiatingProcessId = Column(  
        String(255),  
        comment="Process ID (PID) of the process that initiated the event"  
    )
    AdditionalFields = Column(  
        String(255),  
        comment="Additional information about the event in JSON array format"  
    )
