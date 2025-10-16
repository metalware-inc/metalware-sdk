from metalware_sdk.havoc_common_schema import *
from typing import List


class HavocProject:
  def __init__(self, client: 'HavocClient', project_name: str):
    self._client = client
    self._project_name = project_name

  def set_device_config(self, device_config: DeviceConfig) -> None:
    self._client.set_device_config(self._project_name, device_config)

  def set_fuzzer_config(self, fuzzer_config: FuzzerConfig) -> None:
    self._client.set_fuzzer_config(self._project_name, fuzzer_config)

  def add_image_config(self, image_config: ImageConfig) -> None:
    self._client.add_image_config(self._project_name, image_config)

  def get_runs(self) -> List[RunSummary]:
    return self._client.get_runs(self._project_name)

  def start_run(self, image_name: str, dry_run: bool = False) -> int:
    return self._client.start_run(self._project_name, image_name, dry_run)

  def get_run_status(self, run_id: int) -> RunStatus:
    return self._client.get_run_status(self._project_name, run_id)

  def stop_run(self, run_id: int) -> None:
    self._client.stop_run(self._project_name, run_id)