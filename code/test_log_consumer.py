import unittest
import json
import tempfile
import os
import sys
from unittest.mock import patch, mock_open
from log_consumer import consume_logs


class TestLogConsumer(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_input = os.path.join(self.temp_dir, "test_input.jsonl")
        self.test_output = os.path.join(self.temp_dir, "test_output.json")
        
        # Create test data
        self.test_logs = [
            {"EventID": 1, "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe"},
            {"EventID": 3, "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": ""},
            {"EventID": 999, "Image": "C:\\Tools\\normal.exe", "CommandLine": "normal.exe"},
            {"EventID": 1, "Image": "C:\\Tools\\tunnel.exe", "CommandLine": "tunnel.exe --remote-host example.com"}
        ]
    
    def tearDown(self):
        """Clean up test files"""
        try:
            if os.path.exists(self.test_input):
                os.remove(self.test_input)
            if os.path.exists(self.test_output):
                os.remove(self.test_output)
            os.rmdir(self.temp_dir)
        except OSError:
            pass
    
    def create_test_input_file(self, logs=None):
        """Helper to create test input file"""
        if logs is None:
            logs = self.test_logs
            
        with open(self.test_input, 'w') as f:
            for log in logs:
                f.write(json.dumps(log) + '\n')
    
    def test_consume_logs_normal_operation(self):
        """Test normal log consumption"""
        self.create_test_input_file()
        
        # Should not raise exception
        consume_logs(self.test_input, self.test_output)
        
        # Check output file was created
        self.assertTrue(os.path.exists(self.test_output))
        
        # Check content
        with open(self.test_output, 'r') as f:
            alerts = json.load(f)
        
        # Should detect 3 suspicious events (EventID 1 and 3 are suspicious)
        self.assertGreaterEqual(len(alerts), 3)
    
    def test_consume_logs_file_not_found(self):
        """Test behavior when input file doesn't exist"""
        with patch('sys.exit') as mock_exit:
            consume_logs("nonexistent.jsonl", self.test_output)
            mock_exit.assert_called_with(1)
    
    def test_consume_logs_malformed_json(self):
        """Test handling of malformed JSON"""
        # Create file with malformed JSON
        with open(self.test_input, 'w') as f:
            f.write('{"EventID": 1}\n')  # Valid
            f.write('{"EventID": 2, invalid json\n')  # Invalid
            f.write('{"EventID": 3}\n')  # Valid
        
        # Should handle gracefully
        consume_logs(self.test_input, self.test_output)
        
        # Should still create output file
        self.assertTrue(os.path.exists(self.test_output))
    
    def test_consume_logs_empty_file(self):
        """Test handling of empty input file"""
        # Create empty file
        with open(self.test_input, 'w') as f:
            pass
        
        consume_logs(self.test_input, self.test_output)
        
        # Should create output file with empty array
        with open(self.test_output, 'r') as f:
            alerts = json.load(f)
        
        self.assertEqual(len(alerts), 0)
    
    def test_consume_logs_output_permission_error(self):
        """Test handling of output file permission errors"""
        self.create_test_input_file()
        
        # Mock file open to raise permission error
        with patch('builtins.open', side_effect=[
            open(self.test_input, 'r'),  # Input file opens fine
            PermissionError("Permission denied")  # Output file fails
        ]):
            with patch('sys.exit') as mock_exit:
                consume_logs(self.test_input, self.test_output)
                mock_exit.assert_called_with(1)


if __name__ == '__main__':
    unittest.main()