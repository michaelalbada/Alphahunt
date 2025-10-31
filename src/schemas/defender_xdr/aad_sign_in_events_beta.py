from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .base import Base

class AADSignInEventsBeta(Base):
    __tablename__ = 'AADSignInEventsBeta'
    Timestamp = Column(
        DateTime,
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
    LogonType = Column(
        String(255),
        comment="Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service"
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
    SessionId = Column(
        String(255),
        comment="Unique number assigned to a user by a website's server for the duration of the visit or session"
    )
    AccountDisplayName = Column(
        String(255),
        comment="Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user."
    )
    AccountObjectId = Column(
        String(255),
        comment="Unique identifier for the account in Microsoft Entra ID"
    )
    AccountUpn = Column(
        String(255),
        comment="User principal name (UPN) of the account"
    )
    IsExternalUser = Column(
        Integer,
        comment="Indicates if the user that signed in is external. Possible values: -1 (not set), 0 (not external), 1 (external)."
    )
    IsGuestUser = Column(
        Boolean,
        comment="Indicates whether the user that signed in is a guest in the tenant"
    )
    AlternateSignInName = Column(
        String(255),
        comment="On-premises user principal name (UPN) of the user signing in to Microsoft Entra ID"
    )
    LastPasswordChangeTimestamp = Column(
        DateTime,
        comment="Date and time when the user that signed in last changed their password"
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
    DeviceName = Column(
        String(255),
        comment="Fully qualified domain name (FQDN) of the device"
    )
    AadDeviceId = Column(
        String(255),
        comment="Unique identifier for the device in Microsoft Entra ID"
    )
    OSPlatform = Column(
        String(255),
        comment="Platform of the operating system running on the device. Indicates specific operating systems, including variations within the same family, such as Windows 11, Windows 10, and Windows 7."
    )
    DeviceTrustType = Column(
        String(255),
        comment="Indicates the trust type of the device that signed in. For managed device scenarios only. Possible values are Workplace, AzureAd, and ServerAd."
    )
    IsManaged = Column(
        Integer,
        comment="Indicates whether the device that initiated the sign-in is a managed device (1) or not a managed device (0)"
    )
    IsCompliant = Column(
        Integer,
        comment="Indicates whether the device that initiated the sign-in is compliant (1) or non-compliant (0)"
    )
    AuthenticationProcessingDetails = Column(
        String(255),
        comment="Details about the authentication processor"
    )
    AuthenticationRequirement = Column(
        String(255),
        comment="Type of authentication required for the sign-in. Possible values: multiFactorAuthentication (MFA was required) and singleFactorAuthentication (no MFA was required)."
    )
    TokenIssuerType = Column(
        Integer,
        comment="Indicates if the token issuer is Microsoft Entra ID (0) or Active Directory Federation Services (1)"
    )
    RiskLevelAggregated = Column(
        Integer,
        comment="Aggregated risk level during sign-in. Possible values: 0 (aggregated risk level not set), 1 (none), 10 (low), 50 (medium), or 100 (high)."
    )
    RiskDetails = Column(
        Integer,
        comment="Details about the risky state of the user that signed in"
    )
    RiskState = Column(
        Integer,
        comment="Indicates risky user state. Possible values: 0 (none), 1 (confirmed safe), 2 (remediated), 3 (dismissed), 4 (at risk), or 5 (confirmed compromised)."
    )
    UserAgent = Column(
        String(255),
        comment="User agent information from the web browser or other client application"
    )
    ClientAppUsed = Column(
        String(255),
        comment="Indicates the client app used"
    )
    Browser = Column(
        String(255),
        comment="Details about the version of the browser used to sign in"
    )
    ConditionalAccessPolicies = Column(
        String(255),
        comment="Details of the conditional access policies applied to the sign-in event"
    )
    ConditionalAccessStatus = Column(
        Integer,
        comment="Status of the conditional access policies applied to the sign-in. Possible values are 0 (policies applied), 1 (attempt to apply policies failed), or 2 (policies not applied)."
    )
    IPAddress = Column(
        String(255),
        comment="IP address assigned to the device during communication"
    )
    Country = Column(
        String(255),
        comment="Two-letter code indicating the country/region where the client IP address is geolocated"
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
    NetworkLocationDetails = Column(
        String(255),
        comment="Network location details of the authentication processor of the sign-in event"
    )
    RequestId = Column(
        String(255),
        comment="Unique identifier of the request"
    )
    ReportId = Column(
        String(255),
        comment="Unique identifier for the event"
    )
    EndpointCall = Column(
        String(255),
        comment="Information about the Microsoft Entra ID endpoint that the request was sent to and the type of request sent during sign in."
    )
