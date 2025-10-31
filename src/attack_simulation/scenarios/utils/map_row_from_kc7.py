from urllib.parse import urlparse  
from datetime import datetime
import uuid
import ast
import json
from tqdm import tqdm
import pandas as pd

from src.data_generation.defender_xdr.aad_sign_in_events_beta import AADSignInEventsBeta
from src.data_generation.defender_xdr.device_info import DeviceInfo  
from src.data_generation.defender_xdr.identity_info import IdentityInfo  
from src.data_generation.defender_xdr.device_process_events import DeviceProcessEvents  
from src.data_generation.defender_xdr.device_file_events import DeviceFileEvents  
from src.data_generation.defender_xdr.email_events import EmailEvents  
from src.data_generation.defender_xdr.email_url_info import EmailUrlInfo   
from src.data_generation.defender_xdr.device_network_events import DeviceNetworkEvents  
from src.data_generation.defender_xdr.alert_info import AlertInfo
from src.data_generation.defender_xdr.alert_evidence import AlertEvidence
import random
from datetime import datetime, timedelta


def extract_domain(url):  
    try:  
        parsed_url = urlparse(url)  
        # If netloc is empty, the URL might be missing the scheme  
        if not parsed_url.netloc:  
            parsed_url = urlparse('http://' + url)  
        return parsed_url.netloc  
    except Exception as e:  
        print(f"Error parsing URL: {e}")  
        return None 

def parse_iso8601(timestamp_str):  

    if timestamp_str.endswith('Z'):  
        timestamp_str = timestamp_str[:-1] + '+00:00'  
      
    if ' ' in timestamp_str:  
        timestamp_str = timestamp_str.replace(' ', 'T')  

    if '.' in timestamp_str:  
        main_part, frac_part = timestamp_str.split('.', 1)  
          
        if '+' in frac_part:  
            frac, tz = frac_part.split('+', 1)  
            tz = '+' + tz  
        elif '-' in frac_part[1:]:
            frac, tz = frac_part.split('-', 1)  
            tz = '-' + tz  
        else:  
            frac = frac_part  
            tz = ''  
          
        # Truncate or pad fractional seconds to 6 digits (microseconds)  
        frac = frac[:6].ljust(6, '0')  # Ensures exactly 6 digits  
          
        # Reconstruct the timestamp string  
        timestamp_str = f"{main_part}.{frac}{tz}"  
      
    try:  
        return datetime.fromisoformat(timestamp_str)  
    except ValueError as e:  
        raise ValueError(f"Invalid timestamp format: {timestamp_str}") from e  
def map_row_to_identity_info(row):  
    return IdentityInfo(  
            Timestamp = parse_iso8601(row.get('hire_date') or row.get('timestamp')),    
            AccountObjectId=str(uuid.uuid4()),    
            AccountName=row['email_addr'],    
            AccountDisplayName=row['username'], 
            AccountUpn=row['name'],   
            JobTitle=row['role'],    
            IsAccountEnabled=True,    
            ReportId=str(uuid.uuid4()),
        )   

def map_row_to_device_info(row):
    logged_on_users = [{
        "UserName": row['username'],
        "DomainName": row['company_domain'],
        "Sid": str(uuid.uuid4()),
    }]
    return DeviceInfo(
        Timestamp=datetime.now(),
        DeviceId=str(uuid.uuid4()),
        DeviceName=row['hostname'],
        OSPlatform='Windows10',
        PublicIP=row['ip_addr'],
        LoggedOnUsers=json.dumps(logged_on_users),
    )

def generate_uuids(num_reports):
    return [str(uuid.uuid4()) for _ in range(num_reports)]

def map_row_to_email_info(row):
    return EmailEvents(
        Timestamp=parse_iso8601(row.get('timestamp') or row.get('event_time')),
        NetworkMessageId=row['NetworkMessageId'],
        SenderFromAddress=row['sender'],
        RecipientEmailAddress=row['recipient'],
        Subject=row['subject'],
        UrlCount=1,
    ), EmailUrlInfo(
        Timestamp=parse_iso8601(row.get('timestamp') or row.get('event_time')),
        NetworkMessageId=row['NetworkMessageId'],
        Url=row['link'],
        UrlDomain=extract_domain(row['link']),
    )

def map_row_to_aad_signin_event(row):  
    """  
    Maps a row from authentication.csv to an AADSignInEventsBeta object.  
    """  
    # Parse the timestamp  
    timestamp = parse_iso8601(row['timestamp'])  
      
    correlation_id = str(uuid.uuid4())  
    session_id = str(uuid.uuid4())  
    report_id = str(uuid.uuid4())  
      
    error_code = 0
    if row['result'].lower() == 'failed login':  
        error_code = 500

    user_agent = row.get('user_agent')  
    if pd.isna(user_agent):  
        user_agent = ''
    else:  
        user_agent = str(user_agent)

    # Create the AADSignInEventsBeta instance  
    event = AADSignInEventsBeta(  
        Timestamp=timestamp,  
        ApplicationId=str(uuid.uuid4()), 
        LogonType='Interactive', 
        ErrorCode=error_code,  
        CorrelationId=correlation_id,  
        SessionId=session_id,  
        AccountDisplayName=row['username'],  
        AccountObjectId=str(uuid.uuid4()),
        AccountUpn=row['username'],
        IsExternalUser=0,
        IsGuestUser=False, 
        AlternateSignInName=row['username'], 
        LastPasswordChangeTimestamp=None,
        ResourceDisplayName='Host Machine Login',  
        ResourceId=str(uuid.uuid4()),
        ResourceTenantId=str(uuid.uuid4()),  
        DeviceName=row['hostname'],  
        AadDeviceId=str(uuid.uuid4()),
        IsManaged=1, 
        IsCompliant=1, 
        UserAgent=user_agent,  
        ConditionalAccessPolicies='None', 
        ConditionalAccessStatus=2,
        IPAddress=row['src_ip'],    
        RequestId=str(uuid.uuid4()),
        ReportId=report_id,   
    )  
      
    return event

def map_row_to_device_file_event(row, device_id_map):  
    timestamp = parse_iso8601(row['timestamp'])  
  
    # Retrieve DeviceId based on hostname  
    hostname = row['hostname']  
    device_id = device_id_map.get(hostname, str(uuid.uuid4()))  # Generate a new UUID if not found  
  
    # Create the DeviceFileEvents instance  
    event = DeviceFileEvents(  
        Timestamp=timestamp,  
        DeviceId=device_id,  
        DeviceName=hostname,  
        ActionType='FileCreation',  # Assuming the action is file creation  
        FileName=row.get('filename'),  
        FolderPath=row.get('path'),  
        SHA256=row.get('sha256'),  
        InitiatingProcessFileName=row.get('process_name', 'UnknownProcess')  # Default value  
    )   
  
    return event 

def map_row_to_device_process_event(row, device_id_map):  
    # Parse the timestamp  
    timestamp = parse_iso8601(row['timestamp'])  
  
    # Retrieve DeviceId based on hostname  
    hostname = row['hostname']  
    device_id = device_id_map.get(hostname, str(uuid.uuid4()))  # Generate a new UUID if not found  
  
    # Generate necessary UUIDs or IDs  
    account_object_id = str(uuid.uuid4())  
    initiating_account_object_id = str(uuid.uuid4())  
    report_id = None

    process_commandline = row.get('process_commandline')  
    if pd.isna(process_commandline):  
        process_commandline = ''
    else:  
        process_commandline = str(process_commandline)

    process_name = row.get('process_name')  
    if pd.isna(process_name):  
        process_name = ''
    else:  
        process_name = str(process_name)
  
    # Create the DeviceProcessEvents instance  
    event = DeviceProcessEvents(  
        Timestamp=timestamp,  
        DeviceId=device_id,  
        DeviceName=hostname,  
        ActionType='ProcessCreation',
        FileName=process_name,  
        SHA256=row['process_hash'],   
        ProcessCommandLine=process_commandline,  
        AccountName=row.get('username', ''),  
        AccountObjectId=account_object_id,   
        InitiatingProcessAccountName=row.get('username', ''),  
        InitiatingProcessAccountObjectId=initiating_account_object_id,  
        InitiatingProcessFileName=row['parent_process_name'],  
        ReportId=report_id,  
    )  
  
    return event  

def map_row_to_device_network_event(row, direction):  
    # Parse the timestamp  
    timestamp = parse_iso8601(row['timestamp'])   
  
    # Parse the URL to extract protocol, remote port, and other components  
    parsed_url = urlparse(row['url'])  
    protocol = 'HTTP' if parsed_url.scheme.lower() == 'http' else 'HTTPS' if parsed_url.scheme.lower() == 'https' else parsed_url.scheme.upper()  
    if protocol == 'HTTP':  
        remote_port = 80  
    elif protocol == 'HTTPS':  
        remote_port = 443  
    else:  
        # Default port based on method or leave as None  
        remote_port = None  

    # Populate AdditionalFields with any unmapped data or extra information as JSON  
    additional_fields = {  
        "direction": direction, 
        "status_code": row.get('status_code', None),
        "user_agent": row.get('user_agent')  
    }  
    additional_fields_json = json.dumps(additional_fields)
    
    # Create the DeviceNetworkEvents instance  
    event = DeviceNetworkEvents(  
        Timestamp=timestamp,  
        ActionType='NetworkConnection',
        RemoteIP=row['src_ip'],  
        RemoteUrl=row['url'],  
        AdditionalFields=additional_fields_json,
    )  
  
    return event

def map_row_to_network_flow(row):
    return DeviceNetworkEvents(
        Timestamp=parse_iso8601(row['timestamp']),
        RemoteIP=row['src_ip'],
        RemotePort=row['src_port'],
        LocalIP=row['dest_ip'],
        LocalPort=row['dest_port'],
        Protocol=row['protocol'],
        AdditionalFields=json.dumps({'bytes': row.get('bytes', row.get('num_bytes'))})
    )

def map_row_to_passive_dns(row):
    try:
        timestamp = parse_iso8601(row.get('timestamp'), '')
    except:
        timestamp = datetime.now() + timedelta(seconds=random.randint(0, 3600))
    return DeviceNetworkEvents(
        Timestamp=timestamp,
        RemoteIP=row['ip'],
        RemoteUrl=row['domain'],
    )

def determine_entity_type(indicator):  
    if 'hostname' in indicator:  
        return 'Hostname'  
    elif 'username' in indicator:  
        return 'Username'  
    elif 'sha256' in indicator:  
        return 'SHA256'  
    elif 'filename' in indicator:  
        return 'Filename'  
    elif 'subject' in indicator:  
        return 'Subject'  
    # Add more conditions as necessary  
    else:  
        return 'Unknown'  

def map_row_to_alert_info(row):
    # Generate a unique AlertId  
    AlertId = str(uuid.uuid4())  
      
    # Create the AlertInfo object  
    alert_info = AlertInfo(  
        Timestamp=parse_iso8601(row['timestamp']),  
        AlertId=AlertId,  
        Title=row['description'],  
        Severity=row['severity'],  
    )  
      
    # Initialize AlertEvidence as None  
    alert_evidence = None  
      
    # Check if 'indicators' key exists and is not empty  
    if 'indicators' in row and row['indicators']:  
        try:  
            # Safely evaluate the 'indicators' string to a Python dictionary  
            data = ast.literal_eval(row['indicators'])  
            indicator = data[0] 
              
            # Determine the EntityType based on the data  
            entity_type = determine_entity_type(indicator)  
              
            # Create the AlertEvidence object  
            alert_evidence = AlertEvidence(  
                Timestamp=parse_iso8601(row['timestamp']),  
                AlertId=AlertId,  
                Title=row['description'],  
                EntityType=entity_type,  
                DeviceName=indicator.get('hostname', None),
                FileName=indicator.get('filename', None),
                SHA256=indicator.get('sha256', None),
                EmailSubject=indicator.get('subject', None),
            )  
        except (ValueError, SyntaxError) as e:  
            print(f"Error parsing 'indicators': {e}")  
       
    return alert_info, alert_evidence  
