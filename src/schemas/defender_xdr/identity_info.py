from sqlalchemy import Column, String, Boolean, DateTime, Text
from src.data_generation.defender_xdr.base import Base
  
class IdentityInfo(Base):  
    __tablename__ = 'IdentityInfo'  
  
    Timestamp = Column(
        DateTime,   
        nullable=False,   
        comment="The date and time that the line was written to the database.\n\nThis is used when there are multiple lines for each identity, such as when a change is detected, or if 24 hours have passed since the last database line was added."  
    )
    ReportId = Column(
        String(255),   
        primary_key=True,   
        comment="Unique identifier for the event"  
    )
    AccountObjectId = Column(
        String(255),   
        comment="Unique identifier for the account in Microsoft Entra ID"  
    )
    AccountUpn = Column(
        String(255),   
        comment="User principal name (UPN) of the account"  
    )
    OnPremSid = Column(
        String(255),   
        comment="On-premises security identifier (SID) of the account"  
    )
    AccountDisplayName = Column(
        String(255),   
        comment="Name of the account user displayed in the address book. Typically a combination of a given or first name, a middle initial, and a last name or surname."  
    )
    AccountName = Column(
        String(255),   
        comment="User name of the account"  
    )
    AccountDomain = Column(
        String(255),   
        comment="Domain of the account"  
    )
    Type = Column(
        String(255),   
        comment="Type of record"  
    )
    DistinguishedName = Column(
        String(255),   
        comment="The user's distinguished name"  
    )
    CloudSid = Column(
        String(255),   
        comment="Cloud security identifier of the account"  
    )
    GivenName = Column(
        String(255),   
        comment="Given name or first name of the account user"  
    )
    Surname = Column(
        String(255),   
        comment="Surname, family name, or last name of the account user"  
    )
    Department = Column(
        String(255),   
        comment="Name of the department that the account user belongs to"  
    )
    JobTitle = Column(
        String(255),   
        comment="Job title of the account user"  
    )
    EmailAddress = Column(
        String(255),   
        comment="SMTP address of the account"  
    )
    SipProxyAddress = Column(
        String(255),   
        comment="Voice over IP (VOIP) session initiation protocol (SIP) address of the account"  
    )
    Address = Column(
        String(255),   
        comment="Address of the account user"  
    )
    City = Column(
        String(255),   
        comment="City where the account user is located"  
    )
    Country = Column(
        String(255),   
        comment="Country/Region where the account user is located"  
    )
    IsAccountEnabled = Column(
        Boolean,   
        comment="Indicates whether the account is enabled or not"  
    )
    Manager = Column(
        String(255),   
        comment="The listed manager of the account user"  
    )
    Phone = Column(
        String(50),   
        comment="The listed phone number of the account user"  
    )
    CreatedDateTime = Column(
        DateTime,   
        comment="Date and time when the account user was created"  
    )
    SourceProvider = Column(
        String(255),   
        comment="The identity's source, such as Microsoft Entra ID, Active Directory, or a hybrid identity synchronized from Active Directory to Azure Active Directory"  
    )
    ChangeSource = Column(
        String(255),   
        comment="Identifies which identity provider or process triggered the addition of the new row. For example, the System-UserPersistence value is used for any rows added by an automated process."  
    )
    Tags = Column(
        Text,   
        comment="Tags assigned to the account user by Defender for Identity"  
    )
    AssignedRoles = Column(
        Text,   
        comment="For identities from Microsoft Entra-only, the roles assigned to the account user"  
    )
    TenantId = Column(
        String(255),   
        comment="Unique identifier representing your organization's instance of Microsoft Entra ID"  
    )
    SourceSystem = Column(
        String(255),   
        comment="The source system for the record"  
    )
