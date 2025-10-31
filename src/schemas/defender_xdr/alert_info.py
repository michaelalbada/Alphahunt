from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .base import Base

class AlertInfo(Base):
    __tablename__ = 'AlertInfo'
    
    Timestamp = Column(
        DateTime,
        comment="Date and time when the record was generated"
    )
    AlertId = Column(
        String(255),
        primary_key=True,
        comment="Unique identifier for the alert"
    )
    Title = Column(
        String(255),
        comment="Title of the alert"
    )
    Category = Column(
        String(255),
        comment="Type of threat indicator or breach activity identified by the alert"
    )
    Severity = Column(
        String(255),
        comment="Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert"
    )
    ServiceSource = Column(
        String(255),
        comment="Product or service that provided the alert information"
    )
    DetectionSource = Column(
        String(255),
        comment="Detection technology or sensor that identified the notable component or activity"
    )
    AttackTechniques = Column(
        String(255),
        comment="MITRE ATT&CK techniques associated with the activity that triggered the alert"
    )
