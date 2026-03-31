"""
Tool Runner Utility
Safely executes external binaries (like Go tools: subfinder, httpx, nuclei)
and parses their JSON output.
"""

import subprocess
import json
import os
import shutil
from typing import List, Dict, Any, Generator, Optional

class ToolRunner:
    @staticmethod
    def is_installed(tool_name: str) -> bool:
        """Check if a tool is available in the system PATH."""
        return shutil.which(tool_name) is not None

    @staticmethod
    def run_command(command: List[str], cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        """Run a command synchronously and return the completed process."""
        print(f"[ToolRunner] Executing: {' '.join(command)}")
        try:
            return subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                cwd=cwd,
                check=False
            )
        except Exception as e:
            print(f"[ToolRunner] Execution failed for {' '.join(command)}: {str(e)}")
            return subprocess.CompletedProcess(args=command, returncode=-1, stdout="", stderr=str(e))

    @staticmethod
    def run_command_json_stream(command: List[str], cwd: Optional[str] = None) -> Generator[Dict[str, Any], None, None]:
        """
        Run a command that outputs JSON lines (like httpx or nuclei with -json)
        and yield each line as a parsed dictionary.
        """
        print(f"[ToolRunner] Streaming Exec: {' '.join(command)}")
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                bufsize=1
            )
            
            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # Some tools might print non-JSON info/warnings to stdout despite -silent
                    pass
            
            process.wait()
            if process.returncode != 0:
                err = process.stderr.read()
                if err:
                    print(f"[ToolRunner] Warning: Process exited with code {process.returncode}. Stderr: {err}")
                    
        except Exception as e:
             print(f"[ToolRunner] Stream Execution failed for {' '.join(command)}: {str(e)}")

