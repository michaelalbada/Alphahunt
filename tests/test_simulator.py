# test_simulator.py  
  
import unittest  
import sys  
import os  
import random  
from datetime import datetime, timedelta  
import networkx as nx  
  
# Adjust sys.path to include the project root directory  
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  
if project_root not in sys.path:  
    sys.path.insert(0, project_root)  
  
from src.data_generation.simulator import Simulator  
  
class MockEntity:  
    """A simple mock entity class for testing purposes."""  
    def __init__(self, entity_type, attributes):  
        self.entity_type = entity_type  
        self.attributes = attributes  
  
class TestSimulator(unittest.TestCase):  
    def setUp(self):  
        """Set up a test environment for each test case."""  
        # Seed the random number generator for reproducibility  
        random.seed(42)  
  
        # Create a test network graph  
        self.graph = nx.Graph()  
  
        # Create mock entities  
        self.user_entity = MockEntity('user', {'username': 'test_user'})  
        self.endpoint_entity = MockEntity('endpoint', {'DeviceName': 'test_endpoint', 'PublicIP': '192.168.1.10'})  
        self.process_entity = MockEntity('process', {'process_name': 'test_process', 'pid': 1234, 'parent_pid': 4321})  
  
        # Add entities to the graph as nodes  
        self.graph.add_node(1, entity=self.user_entity)  
        self.graph.add_node(2, entity=self.endpoint_entity)  
        self.graph.add_node(3, entity=self.process_entity)  
  
        # Add edges between nodes to represent relationships  
        self.graph.add_edge(1, 2)  # User connected to Endpoint  
        self.graph.add_edge(2, 3)  # Endpoint connected to Process  
  
        # Initialize the Simulator with the test graph  
        self.simulator = Simulator(self.graph)  
  
    def test_simulate(self):  
        """Test the simulate function."""  
        logs = self.simulator.simulate(simulation_days=1, num_logs_range=(5, 5))  
        self.assertEqual(len(logs), 1)  
        for log_entry in logs:  
            self.assertIn('timestamp', log_entry)  
            self.assertIn('log_details', log_entry)  
            log_details = log_entry['log_details']  
            self.assertIn('log_type', log_details)  
  
    def test_generate_log_details(self):  
        """Test log detail generation."""  
        log_details = self.simulator.generate_log_details()  
        self.assertIsInstance(log_details, dict)  
  
    def test_generate_authentication_log(self):  
        """Test authentication log generation."""  
        log_details = self.simulator.generate_authentication_log()  
        self.assertEqual(log_details['log_type'], 'authentication')  
        self.assertIn('user', log_details)  
        self.assertIn('endpoint', log_details)  
        self.assertIn('result', log_details)  
        self.assertIn('authentication_method', log_details)  
        self.assertIn(log_details['result'], ['success', 'failure'])  
        self.assertIn(log_details['authentication_method'], ['password', 'token', 'biometric'])  
  
    def test_generate_process_creation_log(self):  
        """Test process creation log generation."""  
        log_details = self.simulator.generate_process_creation_log()  
        self.assertEqual(log_details['log_type'], 'process_creation')  
        self.assertIn('process_name', log_details)  
        self.assertIn('pid', log_details)  
        self.assertIn('parent_pid', log_details)  
        self.assertIn('endpoint', log_details)  
  
    def test_get_random_entity_node(self):  
        """Test getting a random entity node."""  
        user_node = self.simulator.get_random_entity_node('user')  
        self.assertIsNotNone(user_node)  
        entity = self.simulator.get_entity(user_node)  
        self.assertEqual(entity.entity_type, 'user')  
  
    def test_get_connected_or_random_node(self):  
        """Test getting a connected or random node."""  
        node = self.simulator.get_connected_or_random_node(1, 'endpoint')  
        self.assertIsNotNone(node)  
        entity = self.simulator.get_entity(node)  
        self.assertEqual(entity.entity_type, 'endpoint')  
  
    def test_get_random_entity_node_excluding(self):  
        """Test getting a random entity node excluding a specific node."""  
        excluded_node = 2  
        node = self.simulator.get_random_entity_node_excluding('endpoint', exclude_node=excluded_node)  
        self.assertIsNone(node)  # Only one endpoint exists and it's excluded  
  
    def test_get_entity(self):  
        """Test retrieving an entity from a node."""  
        entity = self.simulator.get_entity(1)  
        self.assertEqual(entity.entity_type, 'user')  
        self.assertEqual(entity.attributes['username'], 'test_user')  
  
    def test_default_log_handler(self):  
        """Test the default log handler."""  
        log_details = self.simulator.default_log_handler()  
        self.assertEqual(log_details, {})  
  
    def test_simulate_no_entities(self):  
        """Test simulation when no entities are present."""  
        # Empty graph  
        empty_simulator = Simulator(nx.Graph())  
        logs = empty_simulator.simulate(simulation_days=1, num_logs_range=(5, 5))  
        self.assertEqual(len(logs), 0)  
  
if __name__ == '__main__':  
    unittest.main()