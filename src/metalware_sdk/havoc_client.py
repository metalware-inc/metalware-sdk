from metalware_sdk.havoc_common_schema import *
import requests
import base64
from typing import Optional, Tuple, List, Dict, Union
from dataclasses import dataclass
import os

@dataclass
class HavocClient:
  """Client for interacting with the Havoc web server API."""
  base_url: str
  session: requests.Session = requests.Session()

  def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
    url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
    try:
      resp = self.session.request(method, url, **kwargs)
      resp.raise_for_status()
      return resp
    except requests.exceptions.RequestException as e:
      # print the response content
      raise RuntimeError(f"Request to {url} failed: {str(e)}. Response: {resp.text}")

  def upload_file(self, file_path: str, label: str = "unnamed") -> FileMetadata:
    if not os.path.exists(file_path):
      raise FileNotFoundError(f"File not found: {file_path}")
      
    with open(file_path, 'rb') as f:
      file_data = f.read()
      
    # Encode file data as base64
    encoded_data = base64.b64encode(file_data)
    
    # Make request
    resp = self._make_request(
      'POST',
      '/upload-file',
      params={'label': label},
      data=encoded_data
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Ok' in result:
      return FileMetadata.from_dict(result['Ok'])
    else:
      raise RuntimeError(f"Upload failed: {result.get('Err', 'Unknown error')}")

  def infer_memory_config(self, file_hash: str) -> MemoryConfig:
    resp = self._make_request(
      'POST',
      f'/infer-memory-config',
      json=file_hash
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Ok' in result:
      print(result['Ok'])
      return MemoryConfig.from_dict(result['Ok'])
    else:
      raise RuntimeError(f"Memory config inference failed: {result.get('Err', 'Unknown error')}")

  def create_image(self, project_name: str, image_name: str, image_config: ImageConfig) -> str:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/create-image',
      json=image_config.to_dict(),
      params={'name': image_name}
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image creation failed: {result['Err']}")
    else: return result['Ok']

  def create_project(self, project_name: str, config: ProjectConfig, is_overwritable_temp: bool = False) -> None:
    resp = self._make_request(
      'POST',
      '/create-project',
      params={
        'project_name': project_name,
        'is_overwritable_temp': str(is_overwritable_temp).lower()
      },
      json=config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project creation failed: {result['Err']}")

  def start_run(self, project_name: str, config: RunConfig) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/start-run',
      json=config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Run start failed: {result['Err']}")

  def stop_run(self, project_name: str, run_id: int) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/run/{run_id}/stop'
    )
    
    if resp.text != 'OK':
      raise RuntimeError(f"Stop run failed: {resp.text}")

  def get_run_status(self, project_name: str, run_id: int) -> RunSummary:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/summary'
    )
    
    return RunSummary.from_dict(resp.json())

  def get_run_stats(self, project_name: str, run_id: int) -> RunStats:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/stats'
    )
    return RunStats.from_dict(resp.json())