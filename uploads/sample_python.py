import os
import sys
import pickle
import subprocess

# 1. Eval injection
user_input = input("Enter code: ")
eval(user_input)   # VULN: PY-EVAL-REGEX + PY-EVAL-TAINT

# 2. Pickle deserialization
with open("data.pkl", "rb") as f:
    obj = pickle.load(f)  # VULN: PY-PICKLE-LOAD-HEURISTIC

# 3. Subprocess injection
cmd = input("Enter shell command: ")
subprocess.call(cmd, shell=True)  # VULN: PY-SUBPROCESS-SHELL-TAINT

# 4. os.system call
arg = sys.argv[1]
os.system(arg)  # VULN: PY-OS-SYSTEM-AST + PY-SUBPROCESS-SHELL-TAINT