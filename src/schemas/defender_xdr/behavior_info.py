from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .base import Base

class BehaviorInfo(Base):
    __tablename__ = 'BehaviorInfo'
    Timestamp = Column(
        DateTime,
        comment="Date and time when the record was generated"
    )
    BehaviorId = Column(
        String(255),
        primary_key=True,
        comment="Unique identifier for the behavior"
    )
    ActionType = Column(
        String(255),
        comment="Type of behavior"
    )
    Description = Column(
        String(255),
        comment="Description of the behavior"
    )
    Categories = Column(
        String(255),
        comment="Type of threat indicator or breach activity identified by the behavior"
    )
    AttackTechniques = Column(
        String(255),
        comment="MITRE ATT&CK techniques associated with the activity that triggered the behavior"
    )
    ServiceSource = Column(
        String(255),
        comment="Product or service that identified the behavior"
    )
    DetectionSource = Column(
        String(255),
        comment="Detection technology or sensor that identified the notable component or activity"
    )
    DataSources = Column(
        String(255),
        comment="Products or services that provided information for the behavior"
    )
    DeviceId = Column(
        String(255),
        comment="Unique identifier for the device in the service"
    )
    AccountUpn = Column(
        String(255),
        comment="User principal name (UPN) of the account"
    )
    AccountObjectId = Column(
        String(255),
        comment="Unique identifier for the account in Microsoft Entra ID"
    )
    StartTime = Column(
        DateTime,
        comment="Date and time of the first activity related to the behavior"
    )
    EndTime = Column(
        DateTime,
        comment="Date and time of the last activity related to the behavior"
    )
    AdditionalFields = Column(
        String(255),
        comment="Additional information about the behavior"
    )
