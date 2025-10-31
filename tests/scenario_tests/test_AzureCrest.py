import unittest 
import os
import sys
import random
from datetime import datetime, timedelta
import uuid
import pandas as pd 
from tqdm import tqdm
import json
import ast 
from sqlalchemy import create_engine, text  
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  
if project_root not in sys.path:  
    sys.path.insert(0, project_root)  
  
from src.data_generation.defender_xdr.base import Base

class TestDatabasePort(unittest.TestCase):  
    @classmethod  
    def setUpClass(cls):  
        cls.DATABASE_URI = 'mysql+pymysql://datagen:graphgen@localhost:3306/alphahunt'
          
        try:  
            cls.engine = create_engine(cls.DATABASE_URI)  
            cls.connection = cls.engine.connect()  
            print("Database connection established.")  
        except SQLAlchemyError as e:  
            print(f"Error connecting to the database: {e}")  
            raise e 

    def configure_database(database_uri):  
        engine = create_engine(database_uri, echo=False)
        Session = sessionmaker(bind=engine)
        session = Session()

        try:  
            # Drop and recreate tables if needed  
            Base.metadata.drop_all(engine)
            Base.metadata.create_all(engine)
            print("✅ Tables created successfully!")
        except Exception as e:  
            print(f"❌ Error creating tables: {e}")
    
        return engine, session   
  
    @classmethod  
    def tearDownClass(cls):  
        cls.connection.close()  
        cls.engine.dispose()  

    def test_q3(self):
        expected_employee_count = 250

        query = text("""  
            SELECT COUNT(*)  
            FROM IdentityInfo;  
        """)  

        result = self.connection.execute(query).fetchone()  
        actual_employee_count = result[0]
        self.assertEqual(actual_employee_count, expected_employee_count,  
                f"Employee count mismatch: expected '{expected_employee_count}', found '{actual_employee_count}'.")  
        print(f"Employee count test passed: {actual_employee_count} employees found.")
  
    def test_q4(self):    
        expected_cfo_name = 'Penny Pincher'
          
        query = text(f"""  
            SELECT AccountUpn  
            FROM IdentityInfo 
            WHERE JobTitle = "Chief Financial Officer";  
        """)  

        result = self.connection.execute(query).fetchone()  
        actual_cfo_name = result[0]
        self.assertEqual(actual_cfo_name, expected_cfo_name,  
                    f"CFO's name mismatch: expected '{expected_cfo_name}', found '{actual_cfo_name}'.")  
        print(f"CFO name test passed: '{actual_cfo_name}'.")  

    def test_q5(self):  
        recipient_email = 'penny_pincher@azurecresthospital.med'  
        expected_email_count = 30

        query = text(f"""  
            SELECT COUNT(*)  
            FROM EmailEvents  
            WHERE RecipientEmailAddress = "penny_pincher@azurecresthospital.med";  
        """)  

        result = self.connection.execute(query).fetchone()  
        actual_email_count = result[0]
        self.assertEqual(actual_email_count, expected_email_count,  
                    f"Email count mismatch: expected '{expected_email_count}', found '{actual_email_count}'.")  
        print(f"Email count test passed for '{recipient_email}': {actual_email_count} emails received.")  
  
    def test_q6(self):  
        domain = 'pharmabest.net'  
        expected_sender_count = 236

        query = text("""  
            SELECT COUNT(DISTINCT SenderFromAddress)  
            FROM EmailEvents  
            WHERE SenderFromAddress LIKE :domain;  
        """)  

        result = self.connection.execute(query, {'domain': f'%@{domain}'}).fetchone()  
        actual_sender_count = result[0]
        self.assertEqual(actual_sender_count, expected_sender_count,  
                    f"Sender count mismatch: expected '{expected_sender_count}', found '{actual_sender_count}'.")  
        print(f"Sender count test passed for domain '{domain}': {actual_sender_count} distinct senders found.")  

    def test_q7(self):  
        penny_ip = '10.10.0.1'
        expected_website_count = 68

        query = text(f"""  
            SELECT COUNT(DISTINCT RemoteUrl)  
            FROM DeviceNetworkEvents  
            WHERE RemoteIP = "{penny_ip}"
            AND JSON_EXTRACT(AdditionalFields, '$.direction') = 'out';  
        """)  

        result = self.connection.execute(query).fetchone()  
        actual_website_count = result[0]
        self.assertEqual(actual_website_count, expected_website_count,  
                    f"Website count mismatch: expected '{expected_website_count}', found '{actual_website_count}'.")  
        print(f"Website count test passed for IP '{penny_ip}': {actual_website_count} distinct websites visited.")  

    def test_q8(self):  
        keyword = 'health'  
        expected_domain_count = 28

        query = text(f"""  
            SELECT COUNT(DISTINCT RemoteUrl)  
            FROM DeviceNetworkEvents  
            WHERE RemoteUrl LIKE '%{keyword}%'
                AND AdditionalFields IS NULL;  
        """)  

        result = self.connection.execute(query).fetchone()  
        actual_domain_count = result[0]
        self.assertEqual(actual_domain_count, expected_domain_count,  
                    f"Domain count mismatch: expected '{expected_domain_count}', found '{actual_domain_count}'.")  
        print(f"Domain count test passed for keyword '{keyword}': {actual_domain_count} distinct domains found.")  

    def test_q9(self):
        domain = 'bit.ly'

        query = text(f"""  
            SELECT DISTINCT RemoteIP  
            FROM DeviceNetworkEvents  
            WHERE RemoteUrl = "{domain}"  
                AND AdditionalFields IS NULL;  
        """)  

        expected_ips = ['134.177.143.174', '42.143.126.108']  # Replace with actual expected IPs
        result = self.connection.execute(query).fetchall()
        actual_ips = [row[0] for row in result]
        self.assertListEqual(actual_ips, expected_ips,  
            f"IP mismatch: expected '{expected_ips}', found '{actual_ips}'.")  
        print(f"IP resolution test passed for domain '{domain}': {actual_ips}.")

if __name__ == '__main__':  
    unittest.main()  