import json
import sys
import os
from typing import List, Dict, Any
from log_utils import parse_log_line, is_suspicious, validate_json_structure

def consume_logs(input_path: str = 'stream_buffer.jsonl', output_path: str = 'alerts.json') -> None:
    """Process logs and generate alerts with enhanced error handling"""
    alerts: List[Dict[str, Any]] = []
    processed_count = 0
    error_count = 0
    
    try:
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        print(f"[Consumer] Processing logs from {input_path}")
        
        with open(input_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                        
                    log_raw = json.loads(line)
                    
                    # Validate JSON structure
                    if not validate_json_structure(log_raw):
                        print(f"[Consumer] Warning: Invalid structure at line {line_num}")
                        error_count += 1
                        continue
                    
                    parsed = parse_log_line(log_raw)
                    processed_count += 1
                    
                    # More informative logging
                    process_info = parsed['ProcessName'] or parsed['Image'] or 'Unknown'
                    if processed_count % 100 == 0:  # Log every 100 records
                        print(f"[Consumer] Processed {processed_count} records...")
                    
                    if is_suspicious(parsed):
                        print(f"[Consumer] Suspicious Event: EventID {parsed['EventID']} from {process_info}")
                        alerts.append(parsed)
                        
                except json.JSONDecodeError as e:
                    print(f"[Consumer] JSON decode error at line {line_num}: {e}")
                    error_count += 1
                    continue
                except Exception as e:
                    print(f"[Consumer] Error processing line {line_num}: {e}")
                    error_count += 1
                    continue
        
        # Save results
        try:
            with open(output_path, 'w') as out:
                json.dump(alerts, out, indent=2, default=str)
                
            print(f"\n[Consumer] Processing complete:")
            print(f"  Total processed: {processed_count}")
            print(f"  Alerts generated: {len(alerts)}")
            print(f"  Errors encountered: {error_count}")
            print(f"  Results saved to: {output_path}")
            
        except Exception as e:
            print(f"[Consumer] Error saving results: {e}")
            sys.exit(1)
            
    except FileNotFoundError as e:
        print(f"[Consumer] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[Consumer] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "stream_buffer.jsonl"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "alerts.json"
    
    print(f"[Consumer] Starting log analysis: {input_file} -> {output_file}")
    consume_logs(input_file, output_file)