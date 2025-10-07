import unittest
import tempfile
import os
import pandas as pd
import json
import sys
from unittest.mock import patch
from log_producer import stream_logs


class TestLogProducer(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_csv = os.path.join(self.temp_dir, "test_input.csv")
        self.test_output = os.path.join(self.temp_dir, "test_output.jsonl")
        
        # Create test CSV data
        self.test_data = pd.DataFrame({
            'EventID': [1, 3, 11],
            'UtcTime': ['2024-01-15 10:00:00', '2024-01-15 10:01:00', '2024-01-15 10:02:00'],
            'Image': ['C:\\Windows\\cmd.exe', 'C:\\Windows\\svchost.exe', 'C:\\Windows\\notepad.exe'],
            'CommandLine': ['cmd.exe', '', 'notepad.exe sample.txt']
        })
    
    def tearDown(self):
        """Clean up test files"""
        try:
            if os.path.exists(self.test_csv):
                os.remove(self.test_csv)
            if os.path.exists(self.test_output):
                os.remove(self.test_output)
            os.rmdir(self.temp_dir)
        except OSError:
            pass
    
    def create_test_csv(self, data=None):
        """Helper to create test CSV file"""
        if data is None:
            data = self.test_data
        data.to_csv(self.test_csv, index=False)
    
    def test_stream_logs_normal_operation(self):
        """Test normal log streaming operation"""
        self.create_test_csv()
        
        # Stream with no delay for faster testing
        stream_logs(self.test_csv, self.test_output, delay=0)
        
        # Check output file was created
        self.assertTrue(os.path.exists(self.test_output))
        
        # Verify content
        with open(self.test_output, 'r') as f:
            lines = f.readlines()
        
        self.assertEqual(len(lines), 3)  # Should have 3 log entries
        
        # Verify first line is valid JSON
        first_log = json.loads(lines[0])
        self.assertEqual(first_log['EventID'], 1)
        self.assertEqual(first_log['Image'], 'C:\\Windows\\cmd.exe')
    
    def test_stream_logs_file_not_found(self):
        """Test behavior when CSV file doesn't exist"""
        with patch('sys.exit') as mock_exit:
            stream_logs("nonexistent.csv", self.test_output)
            mock_exit.assert_called_with(1)
    
    def test_stream_logs_empty_csv(self):
        """Test handling of empty CSV file"""
        # Create empty CSV
        pd.DataFrame().to_csv(self.test_csv, index=False)
        
        # Should handle gracefully
        stream_logs(self.test_csv, self.test_output, delay=0)
        
        # Output file should exist but be empty
        self.assertTrue(os.path.exists(self.test_output))
        with open(self.test_output, 'r') as f:
            content = f.read()
        self.assertEqual(content.strip(), "")
    
    def test_stream_logs_invalid_csv(self):
        """Test handling of invalid CSV file"""
        # Create invalid CSV
        with open(self.test_csv, 'w') as f:
            f.write("invalid,csv,content\nwith,broken\nstructure")
        
        with patch('sys.exit') as mock_exit:
            stream_logs(self.test_csv, self.test_output)
            mock_exit.assert_called_with(1)
    
    def test_stream_logs_nan_handling(self):
        """Test proper handling of NaN values"""
        # Create CSV with NaN values
        data_with_nan = self.test_data.copy()
        data_with_nan.loc[1, 'CommandLine'] = None
        data_with_nan.loc[2, 'UtcTime'] = None
        
        data_with_nan.to_csv(self.test_csv, index=False)
        
        stream_logs(self.test_csv, self.test_output, delay=0)
        
        # Verify NaN values are converted to null in JSON
        with open(self.test_output, 'r') as f:
            lines = f.readlines()
        
        second_log = json.loads(lines[1])
        third_log = json.loads(lines[2])
        
        self.assertIsNone(second_log['CommandLine'])
        self.assertIsNone(third_log['UtcTime'])


if __name__ == '__main__':
    unittest.main()