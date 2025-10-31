from sqlalchemy import Column, Integer, String, Boolean, DateTime   
from .base import Base  
  
class CloudAppEvents(Base):  
    __tablename__ = 'CloudAppEvents'  
  
    Timestamp = Column(  
        DateTime,  
        nullable=False,  
        comment="Date and time when the event was recorded"  
    )  
    ActionType = Column(  
        String(50),  
        comment="Type of activity that triggered the event"  
    )  
    Application = Column(  
        String(255),  
        comment="Application that performed the recorded action"  
    )  
    ApplicationId = Column(  
        Integer,  
        comment="Unique identifier for the application"  
    )  
    AppInstanceId = Column(  
        Integer,  
        comment="Unique identifier for the instance of an application."  
    )  
    AccountObjectId = Column(  
        String(36),  
        comment="Unique identifier for the account in Microsoft Entra ID"  
    )  
    AccountId = Column(  
        String(255),  
        comment="An identifier for the account as found by Microsoft Defender for Cloud Apps."  
    )  
    AccountDisplayName = Column(  
        String(255),  
        comment="Name displayed in the address book entry for the account user."  
    )  
    IsAdminOperation = Column(  
        Boolean,  
        comment="Indicates whether the activity was performed by an administrator"  
    )  
    DeviceType = Column(  
        String(50),  
        comment="Type of device based on purpose and functionality"  
    )  
    OSPlatform = Column(  
        String(50),  
        comment="Platform of the operating system running on the device"  
    )  
    IPAddress = Column(  
        String(45),  
        comment="IP address assigned to the device during communication"  
    )  
    IsAnonymousProxy = Column(  
        Boolean,  
        comment="Indicates whether the IP address belongs to a known anonymous proxy"  
    )  
    CountryCode = Column(  
        String(2),  
        comment="Two-letter code indicating the country where the client IP address is geolocated"  
    )  
    City = Column(  
        String(255),  
        comment="City where the client IP address is geolocated"  
    )  
    Isp = Column(  
        String(255),  
        comment="Internet service provider associated with the IP address"  
    )  
    UserAgent = Column(  
        String(512),  
        comment="User agent information from the web browser or other client application"  
    )  
    ActivityType = Column(  
        String(50),  
        comment="Type of activity that triggered the event"  
    )  
    ActivityObjects = Column(  
        String(255),  
        comment="List of objects, such as files or folders, that were involved in the recorded activity in JSON format."  
    )  
    ObjectName = Column(  
        String(255),  
        comment="Name of the object that the recorded action was applied to"  
    )  
    ObjectType = Column(  
        String(50),  
        comment="Type of object, such as a file or a folder, that the recorded action was applied to"  
    )  
    ObjectId = Column(  
        String(255),  
        comment="Unique identifier of the object that the recorded action was applied to"  
    )  
    ReportId = Column(  
        String(255),  
        primary_key=True,  
        comment="Unique identifier for the event"  
    )  
    AccountType = Column(  
        String(50),  
        comment="Type of user account, indicating its general role and access levels, such as Regular, System, Admin, Application"  
    )  
    IsExternalUser = Column(  
        Boolean,  
        comment="Indicates whether a user inside the network doesn't belong to the organization's domain"  
    )  
    IsImpersonated = Column(  
        Boolean,  
        comment="Indicates whether the activity was performed by one user for another (impersonated) user"  
    )  
    IPTags = Column(  
        String(255),  
        comment="Customer-defined information applied to specific IP addresses and IP address ranges in JSON format."  
    )  
    IPCategory = Column(  
        String(255),  
        comment="Additional information about the IP address"  
    )  
    UserAgentTags = Column(  
        String(255),  
        comment="More information provided by Microsoft Defender for Cloud Apps in a tag in the user agent field in JSON format."  
    )  
    RawEventData = Column(  
        String(255),  
        comment="Raw event information from the source application or service in JSON format"  
    )  
    AdditionalFields = Column(  
        String(255),  
        comment="Additional information about the entity or event"  
    )  
    LastSeenForUser = Column(  
        String(255),  
        comment="Indicates the number of days since a specific attribute was last seen for the user in JSON format."  
    )  
    UncommonForUser = Column(  
        String(255),  
        comment="Lists the attributes in the event that are considered uncommon for the user in JSON format."  
    )  
    AuditSource = Column(  
        String(255),  
        comment="Audit data source. Possible values are one of the following: Defender for Cloud Apps access control, Defender for Cloud Apps session control, Defender for Cloud Apps app connector"  
    )  
    SessionData = Column(  
        String(255),  
        comment="The Defender for Cloud Apps session ID for access or session control in JSON format."  
    )  
    OAuthAppId = Column(  
        String(255),  
        comment="A unique identifier that is assigned to an application when it is registered to Microsoft Entra with OAuth 2.0 protocol."  
    )