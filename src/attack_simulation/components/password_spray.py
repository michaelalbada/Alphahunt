import random  
from datetime import datetime, timedelta  
from models import DeviceLogonEvents  # Assuming you have a DeviceLogonEvents model  
from sqlalchemy.orm import Session  

class PasswordSprayAttackSimulator:  
    def __init__(self, users, endpoints, passwords=None, success_rate=0.1):  
        """  
        Initialize the simulator with target users, endpoints, and attack parameters.  
  
        :param users: List of user entities to target.  
        :param endpoints: List of endpoint entities to target.  
        :param passwords: List of passwords to try. Defaults to common passwords.  
        :param success_rate: Probability of a successful login per attempt (0 to 1).  
        """  
        self.users = users  
        self.endpoints = endpoints  
        self.passwords = passwords if passwords else [  
            'Password123', 'P@ssw0rd', 'Welcome1', 'Summer2023', 'Spring2023'  
        ]  
        self.success_rate = success_rate  
        self.attempts_per_user = 3  # Number of passwords to try per user  
  
    def simulate_attack(self, session: Session, start_time: datetime, duration: timedelta):  
        """  
        Simulate the password spray attack over the specified duration.  
  
        :param session: SQLAlchemy session object.  
        :param start_time: Start time of the attack simulation.  
        :param duration: Duration over which to spread the attack.  
        """  
        end_time = start_time + duration  
        current_time = start_time  
  
        time_increment = duration / (len(self.users) * self.attempts_per_user)  
  
        for user in self.users:  
            for _ in range(self.attempts_per_user):  
                target_endpoint = random.choice(self.endpoints)  
                password_attempt = random.choice(self.passwords)  
                is_successful = random.random() < self.success_rate  
  
                logon_event = self.create_logon_event(  
                    user,  
                    target_endpoint,  
                    current_time,  
                    is_successful  
                )  
  
                # Write the log to the database  
                session.add(logon_event)  
                session.commit()  
  
                # Increment the time  
                current_time += time_increment  
                if current_time > end_time:  
                    break  
  
    def create_logon_event(self, user, endpoint, timestamp, is_successful):  
        """  
        Create a DeviceLogonEvents object representing a login attempt.  
  
        :param user: The user entity targeted.  
        :param endpoint: The endpoint entity targeted.  
        :param timestamp: The time of the login attempt.  
        :param is_successful: Boolean indicating if the attempt was successful.  
        :return: DeviceLogonEvents instance.  
        """  
        action_type = 'LogonSuccess' if is_successful else 'LogonFailed'  
  
        logon_event = DeviceLogonEvents(  
            Timestamp=timestamp,  
            DeviceId=endpoint.attributes.get('device_id'),  
            DeviceName=endpoint.attributes.get('hostname'),  
            ActionType=action_type,  
            LogonType='RemoteInteractive',  # Password spray attacks are often remote  
            TargetUserName=user.attributes.get('username'),  
            TargetDomainName=user.attributes.get('domain'),  
            TargetUserSid=user.attributes.get('sid'),  
            TargetUserUpn=user.attributes.get('upn'),  
            TargetAccountObjectId=user.attributes.get('object_id'),  
            LogonId=random.randint(1000000, 9999999),  
            IpAddress=self.generate_ip_address(),  
            IsLocalLogon=False,  
            LogonProcessName='User32',  # Common for Windows logons  
            Status='0x0' if is_successful else '0xC000006A',  # Status codes  
            FailureReason=None if is_successful else 'Bad password',  
            InitiatingProcessFileName='lsass.exe',  
            InitiatingProcessId=random.randint(1000, 5000),  
            ReportId=random.randint(1000000000, 9999999999),  
            # Additional fields can be added as needed  
        )
        return logon_event  

    def generate_ip_address(self):
        """  
        Generate a random external IP address to simulate the attacker's IP.  
  
        :return: String representation of an IP address.  
        """  
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"  