from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .base import Base

class CloudAuditEvents(Base):
    __tablename__ = 'CloudAuditEvents'
    Timestamp = Column(
        DateTime,
        comment="Date and time when the event was recorded"
    )
    ReportId = Column(
        String(255),
        primary_key=True,
        comment="Unique identifier for the event"
    )
    DataSource = Column(
        String(255),
        comment="Data source for the cloud audit events, can be GCP (for Google Cloud Platform), AWS (for Amazon Web Services), Azure (for Azure Resource Manager), Kubernetes Audit (for Kubernetes), or other cloud platforms"
    )
    ActionType = Column(
        String(255),
        comment="Type of activity that triggered the event, can be: Unknown, Create, Read, Update, Delete, Other"
    )
    OperationName = Column(
        String(255),
        comment="Audit event operation name as it appears in the record, usually includes both resource type and operation"
    )
    ResourceId = Column(
        String(255),
        comment="Unique identifier of the cloud resource accessed"
    )
    IPAddress = Column(
        String(255),
        comment="The client IP address used to access the cloud resource or control plane"
    )
    IsAnonymousProxy = Column(
        Boolean,
        comment="Indicates whether the IP address belongs to a known anonymous proxy (1) or no (0)"
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
        comment="Internet service provider (ISP) associated with the IP address"
    )
    UserAgent = Column(
        String(512),
        comment="User agent information from the web browser or other client application"
    )
    RawEventData = Column(
        String(255),
        comment="Full raw event information from the data source in JSON format"
    )
    AdditionalFields = Column(
        String(255),
        comment="Additional information about the audit event"
    )
