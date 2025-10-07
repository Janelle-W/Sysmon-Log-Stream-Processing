import pandas as pd
import time
import json
import sys
import os
from typing import Optional
import asyncio

async def stream_logs_async(file_path: str, output_path: str = 'stream_buffer.jsonl', delay: float = 1.0) -> None:
    """Async version of log streaming for better performance"""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")
        
        print(f"[Producer] Loading data from {file_path}")
        df = pd.read_csv(file_path)
        
        if df.empty:
            print("[Producer] Warning: Input file is empty")
            return
        
        print(f"[Producer] Loaded {len(df)} records")
        
        with open(output_path, 'w') as f:
            for idx, (_, row) in enumerate(df.iterrows()):
                try:
                    log = row.to_dict()
                    # Convert NaN values to None for proper JSON serialization
                    log = {k: (None if pd.isna(v) else v) for k, v in log.items()}
                    
                    f.write(json.dumps(log) + '\n')
                    print(f"[Producer] Sent {idx+1}/{len(df)}: EventID {log.get('EventID', 'Unknown')}")
                    
                    if delay > 0:
                        await asyncio.sleep(delay)
                        
                except Exception as e:
                    print(f"[Producer] Error processing row {idx}: {e}")
                    continue
                    
        print(f"[Producer] Completed streaming to {output_path}")
        
    except FileNotFoundError as e:
        print(f"[Producer] Error: {e}")
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print(f"[Producer] Error: {file_path} is empty or invalid CSV")
        sys.exit(1)
    except Exception as e:
        print(f"[Producer] Unexpected error: {e}")
        sys.exit(1)

def stream_logs(file_path: str, output_path: str = 'stream_buffer.jsonl', delay: float = 1.0) -> None:
    """Synchronous wrapper for async streaming"""
    asyncio.run(stream_logs_async(file_path, output_path, delay))

if __name__ == "__main__":
    input_file = sys.argv[1] if len(sys.argv) > 1 else "sample_data.csv"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "stream_buffer.jsonl"
    
    print(f"[Producer] Starting log stream: {input_file} -> {output_file}")
    stream_logs(input_file, output_file)
