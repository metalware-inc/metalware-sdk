# Metalware SDK

Python client SDK for interacting with Metalware [Havoc](https://www.metalware.com/product), a firmware fuzzing platform.

## Installation

### Using pip

```bash
pip install metalware-sdk
```

## Usage

### Basic Example

```python
from metalware_sdk import HavocClient
from metalware_sdk.havoc_common_schema import *

# Connect to a Havoc server
client = HavocClient("http://localhost:8080")

# Upload a firmware file
file_metadata = client.upload_file("path/to/firmware.elf")

# Infer memory configuration from the firmware
memory_config = client.infer_memory_config(file_hash=file_metadata.hash)

# Create a project
project_config = ProjectConfig(memory_config)
client.create_project("my-project", project_config)

# Create an image configuration
image_config = ImageConfig(
    image_arch=ImageArch.CORTEX_M, 
    image_format=ImageFormat(elf=file_metadata.hash)
)
client.create_image(
    project_name="my-project", 
    image_name="default", 
    image_config=image_config
)

# Start a fuzzing run
client.start_run(
    project_name="my-project", 
    config=RunConfig(image_name="default")
)
```

### Running Tests

```bash
# Run all tests
poetry run python -m unittest discover tests

# Run a specific test
poetry run python -m unittest tests.test_havoc
```
