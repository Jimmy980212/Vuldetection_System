# VulDetection

A multi-agent based automated vulnerability detection system for C/C++ codebases, leveraging static analysis tools (Cppcheck, Joern) combined with Large Language Models for intelligent vulnerability classification and validation.

## Features

- **Multi-Agent Architecture**: Five specialized agents working in concert
  - `PreprocessAgent`: Coordinates Cppcheck and Joern static analysis
  - `FeatureAgent`: Extracts semantic features from code context
  - `InferenceAgent`: LLM-powered vulnerability inference and classification
  - `ValidationAgent`: Cross-references findings with CVE knowledge base
  - `ReportAgent`: Generates comprehensive vulnerability reports

- **Dual Static Analysis Engine**: Combines Cppcheck and Joern for comprehensive coverage
  - Cppcheck: Fast, rule-based analysis for common vulnerability patterns
  - Joern: Deep code property graph analysis for complex vulnerabilities

- **LLM-Enhanced Analysis**: Uses DeepSeek Coder API for:
  - Context-aware vulnerability classification
  - False positive reduction
  - Severity assessment with CWE mapping

- **Multiple Output Formats**: Reports in JSON, Markdown, and CSV formats

## Supported Vulnerability Types

| Category | CWE Coverage |
|----------|--------------|
| Buffer Overflow | CWE-120, CWE-121, CWE-122, CWE-119 |
| Null Pointer | CWE-476, CWE-125 |
| Memory Leak | CWE-401, CWE-404 |
| Double Free | CWE-415, CWE-590 |
| Use After Free | CWE-416, CWE-825 |
| Out of Bounds | CWE-787, CWE-125, CWE-126, CWE-193 |
| Integer Overflow | CWE-190, CWE-680, CWE-191 |
| Format String | CWE-134 |
| Command Injection | CWE-78, CWE-77, CWE-74 |
| Race Condition | CWE-362, CWE-367, CWE-667 |
| Path Traversal | CWE-22, CWE-23, CWE-24 |
| And more... |

## Requirements

- **Python**: 3.10 or higher
- **Operating System**: Windows, Linux, macOS
- **Dependencies**: See `requirements.txt`
- **External Tools** (optional):
  - [Cppcheck](http://cppcheck.sourceforge.net/) - Static code analysis
  - [Joern](https://joern.io/) - Code property graph analysis (requires WSL on Windows)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd vuldetection
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install Cppcheck:
   - **Windows**: Download from [cppcheck.sourceforge.net](http://cppcheck.sourceforge.net/)
   - **Linux**: `sudo apt install cppcheck` or `brew install cppcheck`
   - **WSL (for Joern on Windows)**: Install a WSL distribution and Joern

4. (Optional) Install Joern:
   - Follow instructions at [joern.io website](https://joern.io/)
   - On Windows, ensure WSL is configured for Joern execution

5. Configure API credentials:

   Create a `config.json` file in the project root:
```json
{
    "deepseek_api_key": "your-api-key-here"
}
```

   Or set environment variable:
```bash
export DEEPSEEK_API_KEY="your-api-key-here"
```

## Usage

### Basic Usage

```python
from main import run_vulnerability_detection

result = run_vulnerability_detection(
    target_path="/path/to/your/source/code",
    cppcheck_path="/path/to/cppcheck.exe",  # Optional
    enable_joern=True,                       # Set to False if Joern not available
    max_alerts=30,
    analysis_workers=4
)

# Access results
reports = result["reports"]
scan_id = result["scan_id"]
```

### Command Line Usage

```bash
python main.py
```

The system will scan the default test file. Modify `main.py` to scan your own target.

### Running Tests

```bash
pytest test_scripts/ -v
```

## Project Structure

```
vuldetection/
├── agents/                  # Multi-agent components
│   ├── FeatureAgent.py      # Feature extraction agent
│   ├── InferenceAgent.py     # LLM inference agent
│   ├── PreprocessAgent.py    # Static analysis coordinator
│   ├── ValidationAgent.py    # CVE validation agent
│   └── report_agent.py       # Report generation agent
├── core/                    # Core system components
│   ├── base.py              # Base classes and interfaces
│   ├── contracts.py         # Data contracts and schemas
│   ├── models.py            # Data models
│   ├── orchestrator.py      # Agent coordination
│   ├── pipeline.py           # Analysis pipelines
│   └── schema.py             # Schema definitions
├── utils/                   # Utility modules
│   ├── cve_knowledge.py      # CVE knowledge base
│   ├── llm_client.py         # LLM API client
│   ├── llm_gateway.py        # LLM gateway
│   └── structured_logging.py # Logging utilities
├── data/                    # Data files
│   ├── CVE_collection.xlsx   # CVE knowledge database
│   ├── joern_rules.json      # Joern analysis rules
│   └── test_codes/          # Test code samples
├── outputs/                 # Analysis outputs
│   ├── cpg/                  # Code property graphs
│   └── reports/             # Vulnerability reports
├── .github/workflows/        # CI/CD pipelines
├── main.py                  # Entry point
├── requirements.txt          # Python dependencies
└── pytest.ini               # Test configuration
```

## Output

The system generates comprehensive vulnerability reports:

### JSON Report
```json
{
  "scan_id": "20260408_120000_abc123",
  "target_path": "/path/to/code",
  "findings": [
    {
      "file": "vulnerable.c",
      "line": 42,
      "vulnerability_type": "buffer_overflow",
      "cwe": "CWE-120",
      "severity": "high",
      "confidence": 0.85,
      "description": "..."
    }
  ]
}
```

### Risk Levels
- **High**: Critical vulnerabilities requiring immediate attention
- **Medium**: Significant vulnerabilities for review
- **Low**: Minor issues or informational findings
- **Needs Review**: Findings requiring manual verification

## Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_path` | string | required | Path to source code |
| `cppcheck_path` | string | auto | Path to Cppcheck executable |
| `enable_joern` | bool | True | Enable Joern analysis |
| `max_alerts` | int | 30 | Maximum alerts to process |
| `analysis_workers` | int | 4 | Parallel analysis workers |
| `wsl_distro` | string | None | WSL distribution for Joern (Windows) |

## CI/CD Integration

The project includes GitHub Actions workflows for quality gates:

```bash
# Run all quality gates locally
pytest -q -k "schema_gate or performance_gate or precision_gate"
```

## Performance Notes

- **CPG Generation**: Joern generates Code Property Graphs which can be saved for reuse
- **Parallel Processing**: Use `analysis_workers` to control concurrency
- **Alert Limits**: Use `max_alerts` to prevent runaway analysis on large codebases

## License

This project is for educational and research purposes.

## Acknowledgments

- [Cppcheck](http://cppcheck.sourceforge.net/)
- [Joern](https://joern.io/)
- [DeepSeek](https://deepseek.com/) for LLM capabilities
