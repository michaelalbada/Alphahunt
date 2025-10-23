# test_environment_builder.py  
  
import unittest  
import sys  
import os  
import networkx as nx

# Add the project root directory to sys.path  
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  
if project_root not in sys.path:  
    sys.path.insert(0, project_root)  
  
from src.data_generation.environment_builder import (  
    EnvironmentBuilder,  
    HighLevelCompanyProfile,  
    main,  
)  
from sqlalchemy import create_engine  
from sqlalchemy.orm import sessionmaker  
from src.data_generation.defender_xdr.base import Base  
  
class TestEnvironmentBuilder(unittest.TestCase):  
    def setUp(self):  
        # Initialize the EnvironmentBuilder before each test  
        self.builder = EnvironmentBuilder()  
        # Set up an in-memory SQLite database for testing  
        self.engine = create_engine('sqlite:///:memory:')  
        Base.metadata.create_all(self.engine)  
        self.Session = sessionmaker(bind=self.engine)  
        self.session = self.Session()  
  
    def tearDown(self):  
        # Close the session and dispose the engine after each test  
        self.session.close()  
        self.engine.dispose()  
  
    def test_create_company_profile(self):  
        # Test creating a company profile  
        profile = self.builder.create_company_profile()  
        self.assertIsInstance(profile, HighLevelCompanyProfile)  
        for field in profile.__dataclass_fields__:  
            value = getattr(profile, field)  
            self.assertIsInstance(value, str)  
            self.assertTrue(len(value) > 0, f"{field} should not be empty")  
  
    def test_generate_realistic_value(self):  
        # Test generating a realistic value for a field  
        field_name = "IndustryAndMarket"  
        value = self.builder.generate_realistic_value(field_name)  
        self.assertIsInstance(value, str)  
        self.assertTrue(len(value) > 0, f"Value for {field_name} should not be empty")  
  
    def test_create_entities(self):  
        # Test creating entities  
        entities = self.builder.create_entities(self.session)  
        self.assertIsInstance(entities, list)  
        self.assertTrue(len(entities) > 0, "Entities list should not be empty")  
        for entity in entities:  
            self.assertIsNotNone(entity.entity_id)  
            self.assertIsNotNone(entity.entity_type)  
            self.assertIsInstance(entity.attributes, dict)  
  
    def test_assign_users_to_endpoints(self):  
        # Test assigning users to endpoints  
        entities = self.builder.create_entities(self.session)  
        users = [e for e in entities if e.entity_type == 'user']  
        endpoints = [e for e in entities if e.entity_type == 'endpoint']  
        self.builder.assign_users_to_endpoints(users, endpoints)  
        for user in users:  
            self.assertIsNotNone(user.assigned_endpoint)  
            self.assertIn(user.assigned_endpoint, endpoints)  
  
    def test_assign_processes(self):  
        # Test assigning processes to endpoints and users  
        entities = self.builder.create_entities(self.session)  
        users = [e for e in entities if e.entity_type == 'user']  
        endpoints = [e for e in entities if e.entity_type == 'endpoint']  
        processes = [e for e in entities if e.entity_type == 'process']  
        self.builder.assign_users_to_endpoints(users, endpoints)  
        self.builder.assign_processes(processes, endpoints, users)  
        for process in processes:  
            self.assertIsNotNone(process.associated_endpoint)  
            self.assertIsNotNone(process.associated_user)  
            self.assertIn('user', process.attributes)  
  
    def test_generate_digital_estate(self):  
        # Test generating a digital estate  
        estates = self.builder.generate_digital_estate(self.session, num_companies=1)  
        self.assertIsInstance(estates, list)  
        self.assertEqual(len(estates), 1)  
        estate = estates[0]  
        self.assertIn('profile', estate)  
        self.assertIn('entities', estate)  
        self.assertIn('network_graph', estate)  
        self.assertIsInstance(estate['profile'], HighLevelCompanyProfile)  
        self.assertIsInstance(estate['entities'], list)  
        self.assertIsInstance(estate['network_graph'], nx.Graph)  
  
    def test_create_network_topology(self):  
        # Test creating a network topology  
        entities = self.builder.create_entities(self.session)  
        self.builder.create_network_topology(entities, m=2)  
        self.assertIsInstance(self.builder.network_graph, nx.Graph)  
        self.assertEqual(len(self.builder.network_graph.nodes), len(entities))
  
    def test_config_loading(self):  
        # Test loading of the configuration file  
        builder_with_config = EnvironmentBuilder()  
        self.assertIn('num_entities_range', builder_with_config.config)  
        self.assertIn('num_logs_range', builder_with_config.config)  
        self.assertIn('simulation_days', builder_with_config.config)  
  
    def test_nonexistent_config(self):  
        # Test behavior when the config file does not exist  
        # Temporarily rename the config file if it exists  
        config_path = "config/environment_config.yaml"  
        temp_path = "config/environment_config_temp.yaml"  
        if os.path.exists(config_path):  
            os.rename(config_path, temp_path)  
        try:  
            builder_no_config = EnvironmentBuilder()  
            self.assertEqual(builder_no_config.config['num_entities_range'], [50, 200])  
            self.assertEqual(builder_no_config.config['num_logs_range'], [1000, 5000])  
            self.assertEqual(builder_no_config.config['simulation_days'], 30)  
        finally:  
            # Restore the config file  
            if os.path.exists(temp_path):  
                os.rename(temp_path, config_path)  
  
    def test_main_function_output(self):  
        # Test the output of the main() function  
        # Since main() includes visualization which cannot be captured, we modify main() to skip visualization for testing  
        original_visualize_network = self.builder.visualize_network  
        self.builder.visualize_network = lambda: None  # Overwrite with empty function  
        try:  
            import io  
            import sys  
            captured_output = io.StringIO()  
            sys.stdout = captured_output  
            main(database='none')  
            sys.stdout = sys.__stdout__  
            output = captured_output.getvalue()  
            self.assertIn("=== Company Profile ===", output)  
            self.assertIn("=== Sample Entities ===", output)  
            self.assertIn("=== Sample Logs ===", output)  
        finally:  
            # Restore the original visualize_network method  
            self.builder.visualize_network = original_visualize_network  
  
    def test_large_number_of_companies(self):  
        # Test generating multiple companies  
        num_companies = 3  
        estates = self.builder.generate_digital_estate(self.session, num_companies=num_companies)  
        self.assertEqual(len(estates), num_companies)  
        for estate in estates:  
            self.assertIn('profile', estate)  
            self.assertIn('entities', estate)  
            self.assertIn('network_graph', estate)  
  
if __name__ == '__main__':  
    unittest.main()