from metalware_sdk import HavocClient
from metalware_sdk.havoc_common_schema import *

import time

PROJECT_NAME="elf-project"
IMAGE_NAME="default"
HAVOC_ENDPOINT="http://localhost:8080" # FIX ME

# Connect to a Havoc server
client = HavocClient(HAVOC_ENDPOINT)

# House-keeping.
if client.project_exists(PROJECT_NAME):
  print(f"Project {PROJECT_NAME} already exists. Do you want to delete it? (y/n) ", end="")
  if input().lower() == "y":
    client.delete_project(PROJECT_NAME)
    print(f"Project {PROJECT_NAME} deleted.")
  else: exit()

# 1. Upload ELF.
file_metadata = client.upload_file("simple-loop.elf")

# Havoc will infer the device config (memory map) and image config from the ELF.
device_config, image_config = client.infer_config(file_hash=file_metadata.hash)

# 1.1. Check device configuration and modify if necessary.
print(f"Device Config: {device_config}")

# 2. Create a project based on the device config.
client.create_project(
  project_name=PROJECT_NAME,
  config=ProjectConfig(device_config)
)

# 3. Attach image to project based on image config.
print(f"Creating image {IMAGE_NAME}...")

print(f"Image Config: {image_config}")

# Option: Add patches.
# image_config.patches.append(Patch(address=0x20000000, patch_type=PatchType.RETURN))

client.create_project_image(
  project_name=PROJECT_NAME,
  image_name=IMAGE_NAME,
  image_config=image_config
)

# 4. Start a dry run to verify configuration.
run_id = client.start_run(
  project_name=PROJECT_NAME,
  config=RunConfig(image_name=IMAGE_NAME, dry_run=True)
)

while client.get_run_status(PROJECT_NAME, run_id) != RunStatus.FINISHED:
  print(f"Run {run_id} status: {client.get_run_status(PROJECT_NAME, run_id)}")
  time.sleep(1)

print("Dry run completed successfully.")

# 5. Start a fuzzing run.
run_id = client.start_run(
  project_name=PROJECT_NAME,
  config=RunConfig(image_name=IMAGE_NAME, dry_run=False)
)

print(f"Run {run_id} started.")

while client.get_run_status(PROJECT_NAME, run_id) != RunStatus.RUNNING:
  print(f"Run {run_id} status: {client.get_run_status(PROJECT_NAME, run_id)}")
  time.sleep(1)

# 6. Stop the fuzzing run.
client.stop_run(PROJECT_NAME, run_id)

print("Fuzzing stopped.")
