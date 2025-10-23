# 🎯 AlphaHunt: Synthetic Environment Builder

> Generate high-quality synthetic cybersecurity data at scale for training reinforcement learning models in incident investigation, threat hunting, and vulnerability detection.

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/uv-package%20manager-orange)](https://github.com/astral-sh/uv)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Testing](#-testing)
- [Development](#-development)
- [Customization](#-customization)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## 🔍 Overview

AlphaHunt simulates realistic digital environments by creating:
- **Synthetic companies** with organizational structures
- **Entities** including users, processes, and devices
- **Realistic security logs** for training ML models
- **Attack scenarios** across the MITRE ATT&CK framework

## ✨ Features

- 🏢 **Synthetic Company Generation** - Create realistic organizational profiles
- 👥 **Entity Simulation** - Generate users, devices, and processes with relationships
- 📊 **Security Log Generation** - Produce realistic event logs at scale
- 🎭 **Attack Simulation** - Implement full attack chains from reconnaissance to impact
- 🔧 **Highly Configurable** - YAML-based scenario configuration
- ⚡ **Fast & Modern** - Built with uv for lightning-fast dependency management

## 📁 Project Structure
```
Alphahunt/
├── config/                          # YAML scenario configurations
│   ├── environment_config.yaml
│   └── *.yaml                       # Attack chain scenarios
│
├── src/
│   ├── attack_simulation/           # Attack simulation engine
│   │   ├── components/              # MITRE ATT&CK technique implementations
│   │   │   ├── Benign/
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
│   │   └── scenarios/               # KC7 / SimuLand mappings
│   │
│   ├── data_generation/             # Defender-XDR schema builders
│   │   ├── simulator.py             # CLI entry point
│   │   ├── environment_builder.py   # Core environment builder
│   │   └── defender_xdr/            # Schema-specific generators
│   │
│   └── utils/                       # Utilities
│       ├── logging_utils.py
│       ├── config_utils.py
│       └── pydantic_models/         # Data models
│
├── tests/                           # Unit and integration tests
├── pyproject.toml                   # Project dependencies
├── uv.lock                          # Locked versions
└── .python-version                  # Python version pin
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** (managed automatically by uv)
- **uv** package manager

### Installation

**1. Install uv**
```bash
# Linux/WSL/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.cargo/env

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**2. Clone and setup**
```bash
git clone <repository-url>
cd Alphahunt
uv sync
```

That's it! 🎉 The `uv sync` command automatically:
- Creates a virtual environment in `.venv/`
- Installs all dependencies from `uv.lock`
- Sets up the correct Python version

## 💻 Usage

### Generate All Attack Chains
```bash
uv run python src/generate_data.py
```

### Generate Specific Attack Chain
```bash
uv run python src/generate_data.py --config config/initial_access_malware_to_ransomware.yaml
```

### What It Does

The generator:
1. ✅ Creates a synthetic company profile with org structure
2. ✅ Generates entities (users, processes, devices) with relationships
3. ✅ Simulates realistic activity logs over time
4. ✅ Outputs data samples to console (or saves to file)

## ⚙️ Configuration

Configure scenarios using YAML files in `config/`:
```yaml
# config/environment_config.yaml
num_entities_range: [50, 150]    # Entity count range
num_logs_range: [500, 2000]      # Log event count range
simulation_days: 15              # Simulation duration
```

### Available Scenarios

- `initial_access_malware_to_ransomware.yaml` - Ransomware attack chain
- Add more scenarios in `config/` following the same structure

## 🧪 Testing

### Run All Tests
```bash
uv run python -m unittest discover -s tests
```

### Run Specific Test Module
```bash
uv run python -m unittest tests.test_environment_builder
```

### Run With Pytest (if installed)
```bash
uv add --dev pytest
uv run pytest tests/ -v
```

## 🛠️ Development

### Adding Dependencies
```bash
# Production dependency
uv add numpy pandas

# Development dependency  
uv add --dev pytest black ruff

# With version constraint
uv add "requests>=2.31.0"
```

### Updating Dependencies
```bash
# Update all packages
uv lock --upgrade

# Update specific package
uv add package-name --upgrade

# Sync after pulling changes
uv sync
```

### Code Quality
```bash
# Format code
uv add --dev black
uv run black src/ tests/

# Lint code
uv add --dev ruff
uv run ruff check src/ tests/

# Type checking
uv add --dev mypy
uv run mypy src/
```

### View Installed Packages
```bash
uv pip list
```

## 🎨 Customization

### Integrate LLMs for Realistic Data

Add OpenAI for more realistic company profiles and entity attributes:
```bash
uv add openai python-dotenv
```

Create a `.env` file:
```bash
OPENAI_API_KEY=your-api-key-here
```

Update `environment_builder.py`:
```python
import openai
import os
from dotenv import load_dotenv

load_dotenv()

class LLM:
    def __init__(self, model_name='gpt-4', verbose=False):
        self.client = openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.model_name = model_name
        self.verbose = verbose
    
    def __call__(self, messages):
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages
        )
        return response.choices[0].message.content
```

### Add Custom Attack Techniques

1. Create a new module in `src/attack_simulation/components/`
2. Implement the attack logic following MITRE ATT&CK
3. Register it in the scenario configuration YAML

### Extend Entity Types

Add new entity types (network devices, applications, etc.):

1. Extend `create_entities()` in `environment_builder.py`
2. Implement attribute generation in `generate_entity_attributes()`
3. Update `generate_log_details()` for new entity interactions

## 🐛 Troubleshooting

### Command not found: uv

Ensure uv is in your PATH:
```bash
source $HOME/.cargo/env
```
Or restart your terminal.

### Dependencies out of sync

After pulling changes:
```bash
uv sync
```

### Import errors

Always use `uv run` from the project root:
```bash
uv run python src/generate_data.py
```

Verify `__init__.py` files exist in:
- `src/`
- `src/data_generation/`
- `tests/`

### Clean install

If you encounter persistent issues:
```bash
rm -rf .venv uv.lock
uv sync
```

### Python version issues

Check version:
```bash
uv run python --version
```

Pin specific version:
```bash
uv python pin 3.12
uv sync
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**
```bash
   git checkout -b feature/amazing-feature
```
3. **Make your changes**
4. **Run tests and formatting**
```bash
   uv run pytest
   uv run black src/ tests/
   uv run ruff check src/ tests/
```
5. **Commit with descriptive message**
```bash
   git commit -m "Add amazing feature"
```
6. **Push and create Pull Request**
```bash
   git push origin feature/amazing-feature
```

### Development Setup
```bash
git clone <repository-url>
cd Alphahunt
uv sync
uv add --dev pytest black ruff mypy ipython
```

### Commit Checklist

- [ ] Tests pass: `uv run pytest`
- [ ] Code formatted: `uv run black src/ tests/`
- [ ] Linting clean: `uv run ruff check src/ tests/`
- [ ] Dependencies locked: `uv lock` (commit `uv.lock`)
- [ ] Documentation updated

## 📚 Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Defender XDR Schema](https://learn.microsoft.com/en-us/microsoft-365/security/)
- [uv Documentation](https://github.com/astral-sh/uv)