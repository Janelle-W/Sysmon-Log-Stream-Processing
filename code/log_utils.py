import json
import re
from typing import Dict, Any, List

SUSPICIOUS_EVENT_IDS = [1, 3, 11, 4624, 4688, 4663]

# Suspicious patterns for enhanced detection
SUSPICIOUS_PATTERNS = {
    "powershell_encoded": [r"-enc\s+[A-Za-z0-9+/]", r"-encodedcommand\s+[A-Za-z0-9+/]"],
    "suspicious_processes": [r"tunnel\.exe", r"dump\.exe", r"extract\.exe", r"suspicious"],
    "lateral_movement": [r"\\\\[^\\]+\\[A-Za-z]\$", r"net\s+user\s+\w+\s+\w+\s+/add"],
    "suspicious_networks": [r":\d{4}.*-[CR]\s", r"--remote-host", r"--forward"],
    "privilege_escalation": [r"runas", r"--admin", r"whoami\s+/priv"]
}

def parse_log_line(line_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and normalize key fields with error handling"""
    try:
        event_id = line_dict.get("EventID", -1)
        if isinstance(event_id, str):
            event_id = int(event_id) if event_id.isdigit() else -1
        elif not isinstance(event_id, int):
            event_id = -1
            
        return {
            "EventID": event_id,
            "UtcTime": str(line_dict.get("UtcTime", "")),
            "Image": str(line_dict.get("Image", "")),
            "ProcessName": str(line_dict.get("ProcessName", "")),
            "CommandLine": str(line_dict.get("CommandLine", ""))
        }
    except (ValueError, TypeError) as e:
        print(f"Warning: Error parsing log line: {e}")
        return {
            "EventID": -1,
            "UtcTime": "",
            "Image": "",
            "ProcessName": "",
            "CommandLine": ""
        }

def is_suspicious(event: Dict[str, Any]) -> bool:
    """Enhanced suspicious event detection"""
    try:
        # Basic EventID check
        if event["EventID"] in SUSPICIOUS_EVENT_IDS:
            return True
        
        # Enhanced pattern-based detection
        command_line = event.get("CommandLine", "").lower()
        image = event.get("Image", "").lower()
        process_name = event.get("ProcessName", "").lower()
        
        # Combine all text fields for pattern matching
        all_text = f"{command_line} {image} {process_name}"
        
        # Check for suspicious patterns
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.IGNORECASE):
                    return True
        
        return False
        
    except Exception as e:
        print(f"Warning: Error in suspicious detection: {e}")
        return False

def validate_json_structure(data: Dict[str, Any]) -> bool:
    """Validate that log entry has required structure"""
    required_fields = ["EventID"]
    return all(field in data for field in required_fields)