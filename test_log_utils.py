import unittest
import json
from log_utils import parse_log_line, is_suspicious, validate_json_structure


class TestLogUtils(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.valid_log = {
            "EventID": 1,
            "UtcTime": "2024-01-15 09:30:21.123",
            "Image": "C:\\Tools\\sample.exe",
            "ProcessName": "sample.exe",
            "CommandLine": "sample.exe --config test.conf"
        }
        
        self.malformed_log = {
            "EventID": "invalid",
            "UtcTime": None,
            "Image": 123,  # Wrong type
        }
        
        self.suspicious_powershell = {
            "EventID": 4688,
            "CommandLine": "powershell.exe -enc dGVzdCBlbmNvZGVkIGNvbW1hbmQ=",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
    
    def test_parse_log_line_valid(self):
        """Test parsing valid log entry"""
        result = parse_log_line(self.valid_log)
        
        self.assertEqual(result["EventID"], 1)
        self.assertEqual(result["UtcTime"], "2024-01-15 09:30:21.123")
        self.assertIn("sample.exe", result["Image"])
        self.assertIn("sample.exe", result["CommandLine"])
    
    def test_parse_log_line_malformed(self):
        """Test parsing malformed log entry"""
        result = parse_log_line(self.malformed_log)
        
        # Should handle errors gracefully
        self.assertEqual(result["EventID"], -1)
        self.assertIsInstance(result["UtcTime"], str)
        self.assertIsInstance(result["Image"], str)
    
    def test_parse_log_line_missing_fields(self):
        """Test parsing log with missing fields"""
        minimal_log = {"EventID": 3}
        result = parse_log_line(minimal_log)
        
        self.assertEqual(result["EventID"], 3)
        self.assertEqual(result["UtcTime"], "")
        self.assertEqual(result["Image"], "")
        self.assertEqual(result["ProcessName"], "")
        self.assertEqual(result["CommandLine"], "")
    
    def test_is_suspicious_event_id(self):
        """Test suspicious detection by EventID"""
        suspicious_event = {"EventID": 1, "CommandLine": "normal.exe"}
        normal_event = {"EventID": 999, "CommandLine": "normal.exe"}
        
        self.assertTrue(is_suspicious(suspicious_event))
        self.assertFalse(is_suspicious(normal_event))
    
    def test_is_suspicious_powershell_encoded(self):
        """Test detection of encoded PowerShell commands"""
        self.assertTrue(is_suspicious(self.suspicious_powershell))
    
    def test_is_suspicious_tunnel_tool(self):
        """Test detection of tunneling tools"""
        tunnel_event = {
            "EventID": 999,  # Non-suspicious EventID
            "Image": "C:\\Tools\\tunnel.exe",
            "CommandLine": "tunnel.exe --remote-host example.com"
        }
        self.assertTrue(is_suspicious(tunnel_event))
    
    def test_is_suspicious_lateral_movement(self):
        """Test detection of lateral movement patterns"""
        lateral_event = {
            "EventID": 999,
            "CommandLine": "net user testuser password123 /add"
        }
        self.assertTrue(is_suspicious(lateral_event))
    
    def test_is_suspicious_error_handling(self):
        """Test error handling in suspicious detection"""
        malformed_event = {"EventID": None, "CommandLine": None}
        
        # Should not crash and return False for safety
        result = is_suspicious(malformed_event)
        self.assertFalse(result)
    
    def test_validate_json_structure_valid(self):
        """Test JSON structure validation with valid data"""
        self.assertTrue(validate_json_structure(self.valid_log))
    
    def test_validate_json_structure_invalid(self):
        """Test JSON structure validation with invalid data"""
        invalid_log = {"UtcTime": "2019-01-01"}  # Missing EventID
        self.assertFalse(validate_json_structure(invalid_log))
    
    def test_validate_json_structure_empty(self):
        """Test JSON structure validation with empty data"""
        self.assertFalse(validate_json_structure({}))


class TestPatternDetection(unittest.TestCase):
    """Test advanced pattern detection capabilities"""
    
    def test_mimikatz_detection(self):
        """Test detection of credential dumping tools"""
        cred_dump_event = {
            "EventID": 999,
            "Image": "C:\\temp\\suspicious_tool.exe",
            "CommandLine": "suspicious_tool.exe --dump-creds"
        }
        self.assertTrue(is_suspicious(cred_dump_event))
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation attempts"""
        runas_event = {
            "EventID": 999,
            "CommandLine": "runas /user:testadmin cmd.exe"
        }
        self.assertTrue(is_suspicious(runas_event))
    
    def test_suspicious_network_patterns(self):
        """Test detection of suspicious network patterns"""
        tunnel_event = {
            "EventID": 999,
            "CommandLine": "tunnel.exe --port 443 --forward 127.0.0.1:8080"
        }
        self.assertTrue(is_suspicious(tunnel_event))


if __name__ == '__main__':
    unittest.main()