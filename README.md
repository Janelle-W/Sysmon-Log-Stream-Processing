# Sysmon Log Stream Processing Project

This project demonstrates real-time processing and analysis of Windows security event logs (Sysmon data) using Python.

## Overview

The project simulates a security monitoring pipeline that:
1. **Streams log data** from CSV files in real-time
2. **Parses and normalizes** event data
3. **Identifies suspicious events** based on predefined criteria
4. **Generates alerts** for security analysis

## Components

### Core Files
- `log_producer.py` - Simulates real-time log streaming from CSV data
- `log_consumer.py` - Processes incoming logs and generates alerts
- `log_utils.py` - Utility functions for log parsing and suspicious event detection

### Data Files
- `stream_buffer.jsonl` - Temporary buffer for streamed log data (generated)
- `alerts.json` - Generated alerts from suspicious events (generated)
- `sample_data.csv` - Sample security event data for demonstration

## Suspicious Event Detection

The system currently flags these Event IDs as suspicious:
- **EventID 1**: Process creation
- **EventID 3**: Network connection
- **EventID 11**: File create
- **EventID 4624**: Account logon
- **EventID 4688**: Process creation (Windows Security Log)
- **EventID 4663**: Object access attempt

## Data Sanitization

**Important**: All data in this repository has been sanitized for privacy and security:

- Computer names: `PC01/PC02` → `HOST01/HOST02`
- Domain names: `EXAMPLE` → `LAB`
- IP addresses: `10.0.2.x` → `192.168.1.x`
- User accounts: `IEUser` → `user01`
- SIDs: Anonymized with generic values
- Filenames: Generalized to remove specific references

This data is derived from cybersecurity training materials and does not contain real production data.

## Usage

1. **Start the log producer** (simulates real-time log generation):
   ```bash
   python log_producer.py
   ```
   This will process `sample_data.csv` and create `stream_buffer.jsonl`

2. **Run the consumer** (processes logs and generates alerts):
   ```bash
   python log_consumer.py
   ```
   This will analyze `stream_buffer.jsonl` and create `alerts.json`

3. **View alerts** in the generated `alerts.json` file

## Requirements

Install dependencies:
```bash
pip install -r requirements.txt
```

## Running Tests

```bash
python test_log_utils.py
python test_log_consumer.py
python test_log_producer.py
```

## Educational Purpose

This project is designed for:
- Learning security event analysis techniques
- Understanding log processing pipelines
- Practicing real-time data streaming concepts
- Cybersecurity training and education
- Demonstrating suspicious activity detection

**Note**: All data used in this project is synthetic/sanitized for educational purposes. No real sensitive information is included.
