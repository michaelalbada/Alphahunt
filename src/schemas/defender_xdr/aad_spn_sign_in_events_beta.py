from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .base import Base

class AADSpnSignInEventsBeta(Base):
    __tablename__ = 'AADSpnSignInEventsBeta'
    Timestamp = Column(
        DateTime,
        nullable=False,
        comment="Date and time when the record was generated"
    )
    Application = Column(
        String(255),
        comment="Application that performed the recorded action"
    )
    ApplicationId = Column(
        String(255),
        comment="Unique identifier for the application"
    )
    IsManagedIdentity = Column(
        Boolean,
        comment="Indicates whether the sign-in was initiated by a managed identity"
    )
    ErrorCode = Column(
        Integer,
        comment="Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes."
    )
    CorrelationId = Column(
        String(255),
        primary_key=True,
        
        comment="Unique identifier of the sign-in event"
    )
    ServicePrincipalName = Column(
        String(255),
        comment="Name of the service principal that initiated the sign-in"
    )
    ServicePrincipalId = Column(
        String(255),
        comment="Unique identifier of the service principal that initiated the sign-in"
    )
    ResourceDisplayName = Column(
        String(255),
        comment="Display name of the resource accessed. The display name can contain any character."
    )
    ResourceId = Column(
        String(255),
        comment="Unique identifier of the resource accessed"
    )
    ResourceTenantId = Column(
        String(255),
        comment="Unique identifier of the tenant of the resource accessed"
    )
    IPAddress = Column(
        String(255),
        comment="IP address assigned to the endpoint and used during related network communications"
    )
    Country = Column(
        String(255),
        comment="Two-letter code indicating the country where the client IP address is geolocated"
    )
    State = Column(
        String(255),
        comment="State where the sign-in occurred, if available"
    )
    City = Column(
        String(255),
        comment="City where the account user is located"
    )
    Latitude = Column(
        String(255),
        comment="The north to south coordinates of the sign-in location"
    )
    Longitude = Column(
        String(255),
        comment="The east to west coordinates of the sign-in location"
    )
    RequestId = Column(
        String(255),
        comment="Unique identifier of the request"
    )
    ReportId = Column(
        String(255),
        comment="Unique identifier for the event"
    )
