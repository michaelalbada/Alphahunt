from sqlalchemy import Column, BigInteger, String, Boolean, DateTime, Text
from src.data_generation.defender_xdr.base import Base

class DeviceInfo(Base):  
    __tablename__ = 'DeviceInfo'  
  
    Timestamp = Column(  
        DateTime,   
        nullable=False,   
        comment="The date and time that the record was written to the database."  
    )  
    DeviceId = Column(  
        String(64),   
        primary_key=True,  
        comment="Unique identifier of the device (e.g., UUID)."  
    )  
    DeviceName = Column(  
        String(255),  
        comment="Fully qualified domain name (FQDN) of the device."  
    )  
    ClientVersion = Column(  
        String(50),  
        comment="Version of the client software installed on the device."  
    )  
    PublicIP = Column(  
        String(45),  
        comment="Public IP address of the device."  
    )  
    OSArchitecture = Column(  
        String(50),  
        comment="Architecture of the operating system (e.g., x86, x64)."  
    )  
    OSPlatform = Column(  
        String(50),  
        comment="Platform of the operating system (e.g., Windows 10, macOS Catalina)."  
    )  
    OSBuild = Column(  
        BigInteger,  
        comment="Build number of the operating system."  
    )  
    IsAzureADJoined = Column(  
        Boolean,  
        comment="Indicates if the device is joined to Azure Active Directory."  
    )  
    JoinType = Column(  
        String(50),  
        comment="Type of directory join (e.g., AzureAD, Domain)."  
    )  
    AadDeviceId = Column(  
        String(36),   
        comment="Azure Active Directory device ID (UUID)."  
    )  
    LoggedOnUsers = Column(  
        Text,  
        comment="List of users currently logged on to the device in JSON format."  
    )  
    RegistryDeviceTag = Column(  
        String(255),  
        comment="Device tag from the registry."  
    )  
    OSVersion = Column(  
        String(50),  
        comment="Version of the operating system."  
    )  
    MachineGroup = Column(  
        String(255),  
        comment="Group or category to which the machine belongs."  
    )  
    ReportId = Column(  
        BigInteger,  
        comment="Unique identifier for the report or event."  
    )  
    OnboardingStatus = Column(  
        String(50),  
        comment="Status of device onboarding (e.g., Onboarded, NotOnboarded)."  
    )  
    AdditionalFields = Column(  
        Text,  
        comment="Additional information about the device in JSON format."  
    )  
    DeviceCategory = Column(  
        String(50),  
        comment="Category of the device (e.g., Endpoint, Server)."  
    )  
    DeviceType = Column(  
        String(50),  
        comment="Type of device based on purpose and functionality."  
    )  
    DeviceSubtype = Column(  
        String(50),  
        comment="Subtype of the device if applicable."  
    )  
    Model = Column(  
        String(255),  
        comment="Model name or number of the device hardware."  
    )  
    Vendor = Column(  
        String(255),  
        comment="Vendor or manufacturer of the device."  
    )  
    OSDistribution = Column(  
        String(255),  
        comment="Distribution of the operating system (e.g., Windows, Ubuntu)."  
    )  
    OSVersionInfo = Column(  
        String(255),  
        comment="Detailed version information of the operating system."  
    )  
    MergedDeviceIds = Column(  
        Text,  
        comment="List of merged device IDs in JSON format."  
    )  
    MergedToDeviceId = Column(  
        String(255),  
        comment="Device ID to which this device has been merged."  
    )  
    IsInternetFacing = Column(  
        Boolean,  
        comment="Indicates if the device is exposed to the internet."  
    )  
    SensorHealthState = Column(  
        String(50),  
        comment="Health state of the device sensor (e.g., Healthy, Unhealthy)."  
    )  
    IsExcluded = Column(  
        Boolean,  
        comment="Indicates if the device is excluded from certain operations."  
    )  
    ExclusionReason = Column(  
        String(255),  
        comment="Reason the device is excluded."  
    )  
    ExposureLevel = Column(  
        String(50),  
        comment="Exposure level of the device (e.g., High, Medium, Low)."  
    )  
    AssetValue = Column(  
        String(50),  
        comment="Asset value of the device (e.g., Critical, Normal)."  
    )  
    DeviceManualTags = Column(  
        Text,  
        comment="Manual tags assigned to the device in JSON format."  
    )  
    DeviceDynamicTags = Column(  
        Text,  
        comment="Dynamic tags automatically assigned to the device in JSON format."  
    )  
    ConnectivityType = Column(  
        String(50),  
        comment="Type of connectivity (e.g., Connected, Disconnected)."  
    )  
    HostDeviceId = Column(  
        String(255),  
        comment="Identifier of the host device in case of virtual machines."  
    )  
    AzureResourceId = Column(  
        String(255),  
        comment="Azure Resource Manager ID of the device."  
    )  
    AwsResourceName = Column(  
        String(255),  
        comment="AWS resource name associated with the device."  
    )  
    GcpFullResourceName = Column(  
        String(255),  
        comment="Google Cloud Platform full resource name associated with the device."  
    )