from sqlalchemy import Column, Integer, BigInteger, String, Boolean, DateTime  
from sqlalchemy.dialects.mysql import LONGTEXT  
from src.data_generation.defender_xdr.base import Base

class DeviceNetworkInfo(Base):  
    __tablename__ = 'DeviceNetworkInfo'  
  
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
    DeviceId = Column(  
        String(64),
        comment="Unique identifier for the device in the service"
    )  
    DeviceName = Column(  
        String(255),
        comment="Fully qualified domain name (FQDN) of the device"
    )  
    NetworkAdapterName = Column(  
        String(255),
        comment="Name of the network adapter"
    )  
    MacAddress = Column(  
        String(17),
        comment="MAC address of the network adapter"
    )  
    NetworkAdapterType = Column(  
        String(50),
        comment="Network adapter type."
    )  
    NetworkAdapterStatus = Column(  
        String(50),
        comment="Operational status of the network adapter."
    )  
    TunnelType = Column(  
        String(50),
        comment="Tunneling protocol, if the interface is used for this purpose"
    )  
    ConnectedNetworks = Column(  
        LONGTEXT,
        comment="Networks that the adapter is connected to. Each JSON element in the array contains the network name, category (public, private or domain), a description, and a flag indicating if it's connected publicly to the internet."
    )  
    DnsAddresses = Column(  
        LONGTEXT,
        comment="DNS server addresses in JSON array format"
    )  
    IPv4Dhcp = Column(  
        String(45),
        comment="IPv4 address of DHCP server"
    )  
    IPv6Dhcp = Column(  
        String(45),
        comment="IPv6 address of DHCP server"
    )  
    DefaultGateways = Column(  
        LONGTEXT,
        comment="Default gateway addresses in JSON array format"
    )  
    IPAddresses = Column(  
        LONGTEXT,
        comment="JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and IP address space, such as public, private, or link-local"
    )  
    ReportId = Column(  
        BigInteger,
        comment="Event identifier based on a repeating counter. To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns."
    )  
    NetworkAdapterVendor = Column(  
        String(255),
        comment="Name of the manufacturer or vendor of the network adapter"
    )
