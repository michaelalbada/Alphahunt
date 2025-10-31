from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base  
  
Base = declarative_base()  
  
class IdentityLogonEvents(Base):  
    __tablename__ = 'IdentityLogonEvents'  
  
    # Columns  
    Timestamp = Column(  
        DateTime,   
        nullable=False,   
        comment="Date and time when the event was recorded"  
    )  
    ActionType = Column(  
        String(255),   
        comment="Type of activity that triggered the event. See the in-portal schema reference for details"  
    )  
    Application = Column(  
        String(255),   
        comment="Application that performed the recorded action"  
    )  
    LogonType = Column(  
        String(255),   
        comment="Type of logon session. For more information, see Supported logon types."  
    )  
    Protocol = Column(  
        String(50),   
        comment="Network protocol used"  
    )  
    FailureReason = Column(  
        String(255),   
        comment="Information explaining why the recorded action failed"  
    )  
    AccountName = Column(  
        String(255),   
        comment="User name of the account"  
    )  
    AccountDomain = Column(  
        String(255),   
        comment="Domain of the account"  
    )  
    AccountUpn = Column(  
        String(255),   
        comment="User principal name (UPN) of the account"  
    )  
    AccountSid = Column(  
        String(255),   
        comment="Security Identifier (SID) of the account"  
    )  
    AccountObjectId = Column(  
        String(255),   
        comment="Unique identifier for the account in Microsoft Entra ID"  
    )  
    AccountDisplayName = Column(  
        String(255),   
        comment="Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname."  
    )  
    DeviceName = Column(  
        String(255),   
        comment="Fully qualified domain name (FQDN) of the device"  
    )  
    DeviceType = Column(  
        String(50),   
        comment="Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer"  
    )  
    OSPlatform = Column(  
        String(50),   
        comment="Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10 and Windows 7."  
    )  
    IPAddress = Column(  
        String(45),   
        comment="IP address assigned to the endpoint and used during related network communications"  
    )  
    Port = Column(  
        Integer,   
        comment="TCP port used during communication"  
    )  
    DestinationDeviceName = Column(  
        String(255),   
        comment="Name of the device running the server application that processed the recorded action"  
    )  
    DestinationIPAddress = Column(  
        String(45),   
        comment="IP address of the device running the server application that processed the recorded action"  
    )  
    DestinationPort = Column(  
        Integer,   
        comment="Destination port of related network communications"  
    )  
    TargetDeviceName = Column(  
        String(255),   
        comment="Fully qualified domain name (FQDN) of the device that the recorded action was applied to"  
    )  
    TargetAccountDisplayName = Column(  
        String(255),   
        comment="Display name of the account that the recorded action was applied to"  
    )  
    Location = Column(  
        String(255),   
        comment="City, country/region, or other geographic location associated with the event"  
    )  
    Isp = Column(  
        String(255),   
        comment="Internet service provider (ISP) associated with the endpoint IP address"  
    )  
    ReportId = Column(  
        String(255),   
        primary_key=True,   
        comment="Unique identifier for the event"  
    )  
    AdditionalFields = Column(  
        Text,   
        comment="Additional information about the entity or event"  
    )