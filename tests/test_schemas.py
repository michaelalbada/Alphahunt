import unittest  
import sys  
import os
from sqlalchemy import create_engine  
from sqlalchemy.orm import sessionmaker  
from src.data_generation.defender_xdr.base import Base
from datetime import datetime

# import the tables from defender_xdr to load to db
from src.data_generation.defender_xdr.aad_sign_in_events_beta import AADSignInEventsBeta
from src.data_generation.defender_xdr.aad_spn_sign_in_events_beta import AADSpnSignInEventsBeta
from src.data_generation.defender_xdr.alert_evidence import AlertEvidence
from src.data_generation.defender_xdr.alert_info import AlertInfo
from src.data_generation.defender_xdr.behavior_entities import BehaviorEntities
from src.data_generation.defender_xdr.behavior_info import BehaviorInfo
from src.data_generation.defender_xdr.cloud_app_events import CloudAppEvents
from src.data_generation.defender_xdr.cloud_audit_events import CloudAuditEvents
from src.data_generation.defender_xdr.cloud_process_events import CloudProcessEvents

# Add the project root directory to sys.path  
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  
if project_root not in sys.path:  
    sys.path.insert(0, project_root)  
   
class TestSchemas(unittest.TestCase):
    def setUp(self):
        # Set up an in-memory SQLite database for testing  
        self.engine = create_engine('sqlite:///:memory:')  
        Base.metadata.create_all(self.engine)  
        self.Session = sessionmaker(bind=self.engine)  
        self.session = self.Session()  

    def tearDown(self):
        # Close the session and dispose the engine after each test  
        self.session.close()  
        self.engine.dispose()
        
    def test_create_aad_sign_in_events_beta(self):
        event = AADSignInEventsBeta(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), Application='App 1', ApplicationId='AppId1', LogonType='Interactive',
            ErrorCode=0, CorrelationId='CorrId1', SessionId='SessId1', AccountDisplayName='User 1',
            AccountObjectId='ObjId1', AccountUpn='user1@example.com', IsExternalUser=0, IsGuestUser=False,
            AlternateSignInName='user1@onprem.example.com', LastPasswordChangeTimestamp=datetime(2023, 1, 1, 0, 0, 0),
            ResourceDisplayName='Resource 1', ResourceId='ResId1', ResourceTenantId='TenantId1', DeviceName='Device 1',
            AadDeviceId='AadDevId1', OSPlatform='Windows', DeviceTrustType='AzureAd', IsManaged=1, IsCompliant=1,
            AuthenticationProcessingDetails='Details', AuthenticationRequirement='singleFactorAuthentication',
            TokenIssuerType=0, RiskLevelAggregated=1, RiskDetails=0, RiskState=0,
            ClientAppUsed='ClientApp', Browser='Browser', ConditionalAccessPolicies='Policies',
            ConditionalAccessStatus=0, IPAddress='192.168.1.1', Country='US', State='CA', City='San Francisco',
            Latitude='37.7749', Longitude='-122.4194', NetworkLocationDetails='NetworkDetails', RequestId='ReqId1',
            ReportId='RepId1', EndpointCall='EndpointCall'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.Application, 'App 1')
        self.assertEqual(event.ApplicationId, 'AppId1')
        self.assertEqual(event.LogonType, 'Interactive')
        self.assertEqual(event.ErrorCode, 0)
        self.assertEqual(event.CorrelationId, 'CorrId1')
        self.assertEqual(event.SessionId, 'SessId1')
        self.assertEqual(event.AccountDisplayName, 'User 1')
        self.assertEqual(event.AccountObjectId, 'ObjId1')
        self.assertEqual(event.AccountUpn, 'user1@example.com')
        self.assertEqual(event.IsExternalUser, 0)
        self.assertEqual(event.IsGuestUser, False)
        self.assertEqual(event.AlternateSignInName, 'user1@onprem.example.com')
        self.assertEqual(event.LastPasswordChangeTimestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.ResourceDisplayName, 'Resource 1')
        self.assertEqual(event.ResourceId, 'ResId1')
        self.assertEqual(event.ResourceTenantId, 'TenantId1')
        self.assertEqual(event.DeviceName, 'Device 1')
        self.assertEqual(event.AadDeviceId, 'AadDevId1')
        self.assertEqual(event.OSPlatform, 'Windows')
        self.assertEqual(event.DeviceTrustType, 'AzureAd')
        self.assertEqual(event.IsManaged, 1)
        self.assertEqual(event.IsCompliant, 1)
        self.assertEqual(event.AuthenticationProcessingDetails, 'Details')
        self.assertEqual(event.AuthenticationRequirement, 'singleFactorAuthentication')
        self.assertEqual(event.TokenIssuerType, 0)
        self.assertEqual(event.RiskLevelAggregated, 1)
        self.assertEqual(event.RiskDetails, 0)
        self.assertEqual(event.RiskState, 0)
        self.assertEqual(event.ClientAppUsed, 'ClientApp')
        self.assertEqual(event.Browser, 'Browser')
        self.assertEqual(event.ConditionalAccessPolicies, 'Policies')
        self.assertEqual(event.ConditionalAccessStatus, 0)
        self.assertEqual(event.IPAddress, '192.168.1.1')
        self.assertEqual(event.Country, 'US')
        self.assertEqual(event.State, 'CA')
        self.assertEqual(event.City, 'San Francisco')
        self.assertEqual(event.Latitude, '37.7749')
        self.assertEqual(event.Longitude, '-122.4194')
        self.assertEqual(event.NetworkLocationDetails, 'NetworkDetails')
        self.assertEqual(event.RequestId, 'ReqId1')
        self.assertEqual(event.ReportId, 'RepId1')
        self.assertEqual(event.EndpointCall, 'EndpointCall')

    def test_create_aad_spn_sign_in_events_beta(self):
        event = AADSpnSignInEventsBeta(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), Application='App 1', ApplicationId='AppId1',
            ErrorCode=0, CorrelationId='CorrId1',
            ResourceDisplayName='Resource 1', ResourceId='ResId1', ResourceTenantId='TenantId1', IPAddress='192.168.1.1',
            Country='US', State='CA', City='San Francisco', Latitude='37.7749', Longitude='-122.4194',
            RequestId='ReqId1', ReportId='RepId1'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.Application, 'App 1')
        self.assertEqual(event.ApplicationId, 'AppId1')
        self.assertEqual(event.ErrorCode, 0)
        self.assertEqual(event.CorrelationId, 'CorrId1')
        self.assertEqual(event.ResourceDisplayName, 'Resource 1')
        self.assertEqual(event.ResourceId, 'ResId1')
        self.assertEqual(event.ResourceTenantId, 'TenantId1')
        self.assertEqual(event.IPAddress, '192.168.1.1')
        self.assertEqual(event.Country, 'US')
        self.assertEqual(event.State, 'CA')
        self.assertEqual(event.City, 'San Francisco')
        self.assertEqual(event.Latitude, '37.7749')
        self.assertEqual(event.Longitude, '-122.4194')
        self.assertEqual(event.RequestId, 'ReqId1')
        self.assertEqual(event.ReportId, 'RepId1')
    
    def test_create_alert_evidence(self):
        event = AlertEvidence(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), AlertId='Alert1', Title='Alert Title', Categories='["Category1", "Category2"]',
            AttackTechniques='["Technique1", "Technique2"]', ServiceSource='Service Source', DetectionSource='Detection Source',
            EntityType='File', EvidenceRole='Impacted', EvidenceDirection='Source', FileName='file.txt', FolderPath='/path/to/file',
            SHA1='sha1hash', SHA256='sha256hash', FileSize=12345, ThreatFamily='Threat Family', RemoteIP='192.168.1.1',
            RemoteUrl='http://example.com', AccountName='User1', AccountDomain='Domain1', AccountSid='S-1-5-21-1234567890-123456789-1234567890-1234',
            AccountObjectId='ObjId1', AccountUpn='user1@example.com', DeviceId='Device1', DeviceName='Device Name', LocalIP='192.168.1.2',
            NetworkMessageId='MessageId1', EmailSubject='Email Subject', Application='Application', ApplicationId=1, OAuthApplicationId='OAuthAppId1',
            ProcessCommandLine='command line', RegistryKey='Registry Key', RegistryValueName='Registry Value Name', RegistryValueData='Registry Value Data',
            AdditionalFields='Additional Fields', Severity='High', CloudResource='Cloud Resource', CloudPlatform='Azure', ResourceType='Resource Type',
            ResourceID='ResourceId1', SubscriptionId='SubscriptionId1'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.AlertId, 'Alert1')
        self.assertEqual(event.Title, 'Alert Title')
        self.assertEqual(event.Categories, '["Category1", "Category2"]')
        self.assertEqual(event.AttackTechniques, '["Technique1", "Technique2"]')
        self.assertEqual(event.ServiceSource, 'Service Source')
        self.assertEqual(event.DetectionSource, 'Detection Source')
        self.assertEqual(event.EntityType, 'File')
        self.assertEqual(event.EvidenceRole, 'Impacted')
        self.assertEqual(event.EvidenceDirection, 'Source')
        self.assertEqual(event.FileName, 'file.txt')
        self.assertEqual(event.FolderPath, '/path/to/file')
        self.assertEqual(event.SHA1, 'sha1hash')
        self.assertEqual(event.SHA256, 'sha256hash')
        self.assertEqual(event.FileSize, 12345)
        self.assertEqual(event.ThreatFamily, 'Threat Family')
        self.assertEqual(event.RemoteIP, '192.168.1.1')
        self.assertEqual(event.RemoteUrl, 'http://example.com')
        self.assertEqual(event.AccountName, 'User1')
        self.assertEqual(event.AccountDomain, 'Domain1')
        self.assertEqual(event.AccountSid, 'S-1-5-21-1234567890-123456789-1234567890-1234')
        self.assertEqual(event.AccountObjectId, 'ObjId1')
        self.assertEqual(event.AccountUpn, 'user1@example.com')
        self.assertEqual(event.DeviceId, 'Device1')
        self.assertEqual(event.DeviceName, 'Device Name')
        self.assertEqual(event.LocalIP, '192.168.1.2')
        self.assertEqual(event.NetworkMessageId, 'MessageId1')
        self.assertEqual(event.EmailSubject, 'Email Subject')
        self.assertEqual(event.Application, 'Application')
        self.assertEqual(event.ApplicationId, 1)
        self.assertEqual(event.OAuthApplicationId, 'OAuthAppId1')
        self.assertEqual(event.ProcessCommandLine, 'command line')
        self.assertEqual(event.RegistryKey, 'Registry Key')
        self.assertEqual(event.RegistryValueName, 'Registry Value Name')
        self.assertEqual(event.RegistryValueData, 'Registry Value Data')
        self.assertEqual(event.AdditionalFields, 'Additional Fields')
        self.assertEqual(event.Severity, 'High')
        self.assertEqual(event.CloudResource, 'Cloud Resource')
        self.assertEqual(event.CloudPlatform, 'Azure')
        self.assertEqual(event.ResourceType, 'Resource Type')
        self.assertEqual(event.ResourceID, 'ResourceId1')
        self.assertEqual(event.SubscriptionId, 'SubscriptionId1')

    def test_create_alert_info(self):
        event = AlertInfo(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), AlertId='Alert1', Title='Alert Title', Category='Category1',
            Severity='High', ServiceSource='Service Source', DetectionSource='Detection Source',
            AttackTechniques='Technique1'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.AlertId, 'Alert1')
        self.assertEqual(event.Title, 'Alert Title')
        self.assertEqual(event.Category, 'Category1')
        self.assertEqual(event.Severity, 'High')
        self.assertEqual(event.ServiceSource, 'Service Source')
        self.assertEqual(event.DetectionSource, 'Detection Source')
        self.assertEqual(event.AttackTechniques, 'Technique1')

    def test_create_behavior_entities(self):
        event = BehaviorEntities(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), EntityType='Type 1',
            EntityRole='Role 1', BehaviorId='BehaviorId1'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.EntityType, 'Type 1')
        self.assertEqual(event.EntityRole, 'Role 1')
        self.assertEqual(event.BehaviorId, 'BehaviorId1')

    def test_create_behavior_info(self):
        event = BehaviorInfo(
            Timestamp=datetime(2023, 1, 1, 0, 0, 0), BehaviorId='BehaviorId1'
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.BehaviorId, 'BehaviorId1')

    def test_create_cloud_app_events(self):
        event = CloudAppEvents(Timestamp=datetime(2023, 1, 1, 0, 0, 0), ReportId='RepId1')
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.ReportId, 'RepId1')

    def test_create_cloud_audit_events(self):
        event = CloudAuditEvents(Timestamp=datetime(2023, 1, 1, 0, 0, 0), ReportId='RepId1')
        self.session.add(event)
        self.session.commit()
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))
        self.assertEqual(event.ReportId, 'RepId1')
    
    def test_create_cloud_process_events(self):
        event = CloudProcessEvents(
            ProcessId='1', ProcessName='Process 1', ProcessCommandLine='command line', Timestamp=datetime(2023, 1, 1, 0, 0, 0)
        )
        self.session.add(event)
        self.session.commit()
        self.assertEqual(str(event.ProcessId), '1')
        self.assertEqual(event.ProcessName, 'Process 1')
        self.assertEqual(event.ProcessCommandLine, 'command line')
        self.assertEqual(event.Timestamp, datetime(2023, 1, 1, 0, 0, 0))


if __name__ == '__main__':  
    unittest.main()