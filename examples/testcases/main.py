
from metalware_sdk import HavocClient
from metalware_sdk.havoc_common_schema import *
import time

PROJECT_NAME   = "coffee1" # TODO: FIX ME
HAVOC_ENDPOINT = "http://localhost:8080" # TODO: FIX ME
RUN_ID         = 4 # TODO: FIX ME

# Connect to a Havoc server
client = HavocClient(HAVOC_ENDPOINT)

testcases = client.get_testcases(project_name=PROJECT_NAME, run_id=RUN_ID)

print(f"Testcases:")
MAX_TESTCASES = 10

for testcase in testcases[:MAX_TESTCASES]:
  print(f"ID: {testcase.input_id}")
  print(f"Exit reason: {testcase.exit_reason}")
  print(f"Exit PC: {testcase.exit_pc}")
  print(f"Num blocks: {testcase.num_blocks}")
  print(f"Timestamp: {testcase.timestamp}")
  print(f"")

if len(testcases) > 0:
  print(f"Dumping testcase input: {testcases[0].input_id}")
  input = client.get_testcase_input(project_name=PROJECT_NAME, run_id=RUN_ID, testcase_id=testcases[0].input_id)
  print(input)