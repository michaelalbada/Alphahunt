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
        table_name = 'IdentityInfo'  
        expected_count = 500
        query = text("SELECT COUNT(*) FROM IdentityInfo")

        result = self.connection.execute(query).scalar()  
        self.assertEqual(result, expected_count,  
                            f"Expected {expected_count} rows in {table_name}, found {result}.")  
        print(f"Row count test passed for table '{table_name}'.")     

    def test_q4(self):  
        role = 'CTO'  
        expected_cto_name = 'Alexis Khoza'
          
        query = text(f"""  
            SELECT AccountUpn  
            FROM IdentityInfo 
            WHERE JobTitle = "CTO";  
        """)  

        result = self.connection.execute(query).fetchone()  
        self.assertIsNotNone(result, f"No employee found with role '{role}'.")  
        actual_cto_name = result[0]
        self.assertEqual(actual_cto_name, expected_cto_name,  
                            f"CTO's name mismatch: expected '{expected_cto_name}', found '{actual_cto_name}'.")  
        print(f"CTO name test passed: '{actual_cto_name}'.")  

    def test_q5(self):

        expected_email_count = 31

        query = text(f"""
            SELECT COUNT(*)
            FROM EmailEvents
            WHERE RecipientEmailAddress = "alexis_khoza@solvisystems.com"
        """)

        result = self.connection.execute(query).scalar()
        self.assertEqual(result, expected_email_count,
                            f"Expected {expected_email_count} emails sent to Alexis Khoza, found {result}.")
        print(f"Email count test passed for Alexis Khoza.")
    
    def test_q6(self):
        expected_sender_count = 745  # Replace with your expected count

        query = text(f"""
            SELECT COUNT(DISTINCT SenderFromAddress)
            FROM EmailEvents
            WHERE SenderFromAddress LIKE '%@eskom.co.za'
        """)

        result = self.connection.execute(query).scalar()
        self.assertEqual(result, expected_sender_count,
                    f"Expected {expected_sender_count} distinct senders from eskom.co.za, found {result}.")
        print(f"Distinct sender count test passed for eskom.co.za.")
    
    def test_q7(self):
        alexis_khoza_ip = '10.10.0.7'
        expected_website_count = 72

        query = text(f"""
            SELECT COUNT(DISTINCT RemoteUrl)
            FROM DeviceNetworkEvents
            WHERE RemoteIP = '{alexis_khoza_ip}'
              AND JSON_EXTRACT(AdditionalFields, '$.direction') = 'out'
        """)

        result = self.connection.execute(query).scalar()
        self.assertEqual(result, expected_website_count,
                            f"Expected {expected_website_count} distinct websites visited by Alexis Khoza, found {result}.")
        
    def test_q8(self):
        expected_count = 19
        query = text("""
            SELECT COUNT(DISTINCT RemoteUrl)
            FROM DeviceNetworkEvents
            WHERE RemoteUrl LIKE '%real%'
                AND AdditionalFields IS NULL
        """)
        result = self.connection.execute(query).scalar()
        self.assertEqual(result, expected_count,
                            f"Expected {expected_count} distinct domains containing 'real', found {result}.")
        print("Distinct domain count test passed for 'real'.")

    def test_q9(self):
        query = text("""
            SELECT DISTINCT RemoteIP
            FROM DeviceNetworkEvents
            WHERE RemoteUrl = 'bit.ly'
                AND Protocol IS NULL
        """)
        
        ips = [
            "30.99.71.8",
            "179.251.245.106",
            "179.14.26.208",
            "22.151.219.153",
            "144.69.121.139",
            "181.216.241.104",
            "219.82.23.42",
            "146.146.40.67",
            "216.78.8.45",
            "198.1.135.250"
        ]

        result = self.connection.execute(query).fetchall()
        result_ips = [row[0] for row in result]
        self.assertCountEqual(result_ips, ips, "IP list mismatch for 'bit.ly'.")
        print(f"All IPs matched for 'bit.ly': {result_ips}")

if __name__ == '__main__':  
    unittest.main()  