import yaml
from copy import deepcopy

def load_and_merge_config(yaml_path, overrides=None):
    """
    Load a YAML config file and recursively merge in any overrides.
    Args:
        yaml_path (str): Path to the YAML file.
        overrides (dict, optional): Dict of values to override in the loaded config.
    Returns:
        dict: The merged configuration.
    """
    with open(yaml_path, "r") as f:
        base_config = yaml.safe_load(f)
    config = deepcopy(base_config)
    if overrides:
        def deep_merge(dct, merge_dct):
            for k, v in merge_dct.items():
                if (k in dct and isinstance(dct[k], dict) and isinstance(v, dict)):
                    deep_merge(dct[k], v)
                else:
                    dct[k] = v
        deep_merge(config, overrides)
    return config 