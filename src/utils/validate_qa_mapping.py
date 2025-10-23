import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
import importlib
import yaml
import argparse


def main():
    parser = argparse.ArgumentParser(description="Validate that all QA YAML questions have answer functions.")
    parser.add_argument("--yaml", required=True, help="Path to the QA YAML file.")
    parser.add_argument("--step-class", required=True, help="Python import path to the step class (e.g. src.attack_simulation.components.Persistence.boot_logon_autostart_execution.BootLogonAutostartExecutionAttackStep)")
    args = parser.parse_args()

    # Load YAML
    with open(args.yaml, "r") as f:
        qa_list = yaml.safe_load(f)
    yaml_ids = {entry["id"] for entry in qa_list}

    # Import the class and instantiate
    module_path, class_name = args.step_class.rsplit('.', 1)
    module = importlib.import_module(module_path)
    step_class = getattr(module, class_name)
    dummy_config = {"benign_data": {}, "victims": [], "attacker": {}, "last_scan_time": "2024-01-01T00:00:00"}
    instance = step_class(dummy_config)
    answer_mapping = instance.ANSWER_FUNCTIONS
    code_ids = set(answer_mapping.keys())

    missing_in_code = yaml_ids - code_ids
    extra_in_code = code_ids - yaml_ids

    if missing_in_code:
        print(f"ERROR: The following question IDs are in the YAML but missing in code: {missing_in_code}")
    if extra_in_code:
        print(f"WARNING: The following answer functions are in code but not in the YAML: {extra_in_code}")
    if not missing_in_code:
        print("All YAML questions are covered by answer functions.")

    # Optional: check that each mapping value has a callable 'func'
    for qid, entry in answer_mapping.items():
        if not callable(entry.get("func", None)):
            print(f"ERROR: ANSWER_FUNCTIONS[{qid}] does not have a callable 'func'.")

if __name__ == "__main__":
    main() 