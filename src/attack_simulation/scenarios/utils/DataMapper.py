from tqdm import tqdm  
from sqlalchemy.orm import Session  
  
from src.data_generation.defender_xdr.device_info import DeviceInfo  
from src.attack_simulation.scenarios.utils.map_row_from_kc7 import (  
    map_row_to_identity_info,  
    map_row_to_device_info,  
    map_row_to_email_info,  
    map_row_to_aad_signin_event,  
    map_row_to_device_file_event,  
    map_row_to_device_process_event,  
    map_row_to_device_network_event,  
    map_row_to_alert_info,  
    map_row_to_passive_dns, 
    map_row_to_network_flow, 
    generate_uuids,  
) 

class DataMapper:  
    def __init__(self, session: Session):   
        self.session = session  
  
    def map_identity_info(self, identities):  
        mapped_identities = [  
            map_row_to_identity_info(row)  
            for _, row in tqdm(identities.iterrows(), desc="Mapping Identities")  
        ]  
        self.session.bulk_save_objects(mapped_identities)  
        self.session.commit()  
        print("✅ Identities inserted successfully!")  
  
    def map_devices(self, identities):  
        mapped_devices = [  
            map_row_to_device_info(row)  
            for _, row in tqdm(identities.iterrows(), desc="Mapping Devices")  
        ]  
        self.session.bulk_save_objects(mapped_devices)  
        self.session.commit()  
        print("✅ Devices inserted successfully!")  
  
    def map_emails(self, emails):  
        emails['NetworkMessageId'] = generate_uuids(len(emails))  
        email_infos = [  
            map_row_to_email_info(row)  
            for _, row in tqdm(emails.iterrows(), desc="Mapping Emails")  
        ]  
        email_events, email_urls = zip(*email_infos)  # Unzips the list of tuples  
        self.session.bulk_save_objects(email_events)  
        self.session.bulk_save_objects(email_urls)  
        self.session.commit()  
        print("✅ Emails inserted successfully!")  
  
    def map_authentication_events(self, authentication_events):  
        mapped_auth_events = [  
            map_row_to_aad_signin_event(row)  
            for _, row in tqdm(authentication_events.iterrows(), desc="Mapping Authentication Events")  
        ]  
        self.session.bulk_save_objects(mapped_auth_events)  
        self.session.commit()  
        print("✅ Authentication events inserted successfully!")  
  
    def _get_device_id_map(self):   
        devices = self.session.query(DeviceInfo.DeviceName, DeviceInfo.DeviceId).all()  
        return {device.DeviceName: device.DeviceId for device in devices}  
  
    def map_file_events(self, device_file_events):   
        device_id_map = self._get_device_id_map()  
        mapped_file_events = [  
            map_row_to_device_file_event(row, device_id_map)  
            for _, row in tqdm(device_file_events.iterrows(), desc="Mapping File Events")  
        ]  
        self.session.bulk_save_objects(mapped_file_events)  
        self.session.commit()  
        print("✅ File events inserted successfully!")  
  
    def map_process_events(self, device_process_events):   
        device_id_map = self._get_device_id_map()  
        mapped_process_events = [  
            map_row_to_device_process_event(row, device_id_map)  
            for _, row in tqdm(device_process_events.iterrows(), desc="Mapping Process Events")  
        ]  
        self.session.bulk_save_objects(mapped_process_events)  
        self.session.commit()  
        print("✅ Process events inserted successfully!")  
  
    def map_network_events(self, network_events, direction: str):  
        mapped_network_events = [  
            map_row_to_device_network_event(row, direction)  
            for _, row in tqdm(network_events.iterrows(), desc=f"Mapping {'Inbound' if direction == 'in' else 'Outbound'} Network Events")  
        ]  
        self.session.bulk_save_objects(mapped_network_events)  
        self.session.commit()  
        dir_str = "Inbound" if direction == "in" else "Outbound"  
        print(f"✅ {dir_str} network events inserted successfully!")  

    def map_network_flow(self, network_flows):
        mapped_network_flows = [  
            map_row_to_network_flow(row)  
            for _, row in tqdm(network_flows.iterrows(), desc="Mapping Network Flows")  
        ]  
        self.session.bulk_save_objects(mapped_network_flows)  
        self.session.commit()  
        print("✅ Network flows inserted successfully!")
  
    def map_alerts(self, alerts):   
        alert_infos = [  
            map_row_to_alert_info(row)  
            for _, row in tqdm(alerts.iterrows(), desc="Mapping Alerts")  
        ]  
        alert_info, alert_evidence = zip(*alert_infos) 
        self.session.bulk_save_objects(alert_info)  
        if alert_evidence[0] is not None:
            self.session.bulk_save_objects(alert_evidence)  
        self.session.commit()  
        print("✅ Alerts inserted successfully!")  
  
    def map_passive_dns(self, passive_dns):  
        mapped_passive_dns = [  
            map_row_to_passive_dns(row)  
            for _, row in tqdm(passive_dns.iterrows(), desc="Mapping Passive DNS Events")  
        ]  
        self.session.bulk_save_objects(mapped_passive_dns)  
        self.session.commit()  
        print("✅ Passive DNS events inserted successfully!")  