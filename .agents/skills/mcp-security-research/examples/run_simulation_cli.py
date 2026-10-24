#!/usr/bin/env python3
import subprocess
import sys
import os

def run_simulation(script_name, model_name="qwen2.5:7b", custom_prompt=None):
    """
    Runs a security research simulation script with set environment variables.
    """
    script_path = os.path.abspath(script_name)
    if not os.path.exists(script_path):
        print(f"Error: Script '{script_name}' not found in the workspace.")
        sys.exit(1)
        
    env = os.environ.copy()
    env["SELECTED_MODEL"] = model_name
    env["MCP_TYPE"] = "Local Filesystem"
    env["UI_LANGUAGE"] = "uk"
    
    if custom_prompt:
        env["CUSTOM_PROMPT"] = custom_prompt
        
    print(f"🚀 Running {script_name} using model {model_name}...")
    try:
        # Run using python executable from the virtual environment if available, otherwise fallback to system python
        python_exec = sys.executable
        process = subprocess.run([python_exec, script_name], env=env)
        print(f"\n✅ Simulation finished with exit code {process.returncode}")
    except KeyboardInterrupt:
        print("\n🛑 Simulation terminated by user.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_simulation_cli.py <script_name> [model_name] [custom_prompt]")
        print("Example: python run_simulation_cli.py attack_sim.py qwen2.5:7b 'Read report.txt'")
        sys.exit(1)
        
    script = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else "qwen2.5:7b"
    prompt = sys.argv[3] if len(sys.argv) > 3 else None
    
    run_simulation(script, model, prompt)
