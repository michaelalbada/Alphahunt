# AlphaHunt: Synthetic Environment Builder
 
### The Synthetic Environment Builder is a tool designed to generate high-quality synthetic data at scale for cybersecurity applications. It simulates digital environments by creating synthetic companies, entities (users, processes, devices), and realistic logs. This data can be used to train reinforcement learning models for tasks like incident investigation, threat hunting, and detecting vulnerabilities.

## Table of Contents
 
Project Structure
Prerequisites
Installation
Usage
Running the Environment Builder
Running Unit Tests
Configuration
Customization and Extension
Troubleshooting
Contributing

## Project Structure

project-root/
├── config/                             # YAML files that describe scenarios
│   └── *.yaml
│
├── src/
│   ├── attack_simulation/               # end-to-end attack simulator
│   │   ├── components/                  # atomic generators & helpers
│   │   │   ├── Benign / benign.py
│   │   │   ├── Reconnaissance/
│   │   │   ├── InitialAccess/
│   │   │   ├── CredentialAccess/
│   │   │   ├── Execution/
│   │   │   ├── LateralMovement/
│   │   │   ├── Collection/
│   │   │   ├── CommandAndControl/
│   │   │   ├── Exfiltration/
│   │   │   ├── Impact/
│   │   │   └── Persistence/
│   │   │
│   │   └── scenarios/                    # KC7 / SimuLand mapping utilities
│   │
│   ├── data_generation/                 # Defender-XDR schema & builders
│   │   ├── simulator.py                 # CLI entry-point for bulk generation
│   │   ├── environment_builder.py
│   │   └── defender_xdr/ …              # schema-specific generators
│   │
│   └── utils/
│       ├── logging_utils.py
│       ├── config_utils.py
│       └── pydantic_models/             # common Pydantic schemas
│
├── tests/                               # unit / integration tests
│   ├── __init__.py
│   └── test_*.py                        # e.g. test_attack_steps.py
│
└── README.md                            # high-level documentation
 
## ☝️ Installation

0. Install uv

`curl -LsSf https://astral.sh/uv/install.sh | sh`
`source $HOME/.cargo/env`

1. Set up the enviornment

    uv sync

## 🧪 Usage

To generate synthetic data for each of the attack chains available simply run:

`uv run python src/generate_data.py`

To generate data for a specific attack chain, just specify the file under configs:

`uv run python src/generate_data.py --config config/initial_access_malware_to_ransomware.yaml`

This script:

Creates a synthetic company profile.
Generates entities such as users, processes, and devices.
Simulates logs of activities within the environment.
Prints samples of the generated data to the console.

## Running Tests

Option 1: Using unittest Discovery
 
Run all tests in the tests/ directory:


python -m unittest discover -s tests  
 

Option 2: Running a Specific Test Module
 
Run the test_environment_builder.py module:


python -m unittest tests.test_environment_builder  
 

Option 3: Directly Running the Test Script
 
Execute the test script directly:


python tests/test_environment_builder.py  
 

## Configuration
 
The environment builder can be customized using a configuration file. The default likes under config/environment_config.yaml.


num_entities_range: [50, 150]    # Range for the number of entities to generate  
num_logs_range: [500, 2000]      # Range for the number of logs to generate  
simulation_days: 15              # Number of days to simulate  
 
The script will use default settings if the configuration file is not provided or if specific settings are missing.


## Integrate with Language Models (LLMs)
 
The current implementation uses mock data for generating company profiles and other attributes. To generate more realistic and varied data, you can integrate a Language Model (e.g., OpenAI's GPT-3 or GPT-4).

Modify the LLM class in environment_builder.py:


class LLM:  
    def __init__(self, model_name='gpt-4', verbose=False):  
        # Initialize the LLM API client here  
        pass  
  
    def __call__(self, messages):  
        # Implement the API call to the LLM and return the response  
        pass  
 
Ensure you handle API keys and environment variables appropriately.

## Simulate Cyberattacks
 
Extend the environment builder to simulate cyberattacks:

Define attack patterns and behaviors.
Generate logs that reflect malicious activities.
Label data for supervised learning or reinforcement learning tasks.
Add More Entity Types
 
You can add more entity types (e.g., network devices, applications) by:

Extending the create_entities method.
Implementing new cases in generate_entity_attributes.
Updating generate_log_details to include new entity interactions.


## Troubleshooting
 
Confirm that you're running scripts from the project root directory.
Verify that __init__.py files exist in src/, src/data_generation/, and tests/ directories.

Import Errors in Tests
 
If the tests fail due to import errors:

Check that the import statements match the package structure:


from data_generation.environment_builder import EnvironmentBuilder, HighLevelCompanyProfile  
 

Ensure that the tests directory contains an __init__.py file.

 
## Contributing
 
Contributions are welcome!
