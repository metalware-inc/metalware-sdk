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
      raise RuntimeError(f"Request to {url} failed: {str(e)}.")

  def get_projects(self) -> List[Tuple[str, int]]:
    resp = self._make_request('GET', '/projects')
    return resp.json()

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

  def infer_config(self, file_hash: str) -> [DeviceConfig, ImageConfig]:
    resp = self._make_request(
      'POST',
      f'/infer-memory-layout-and-entry',
      json=file_hash
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Ok' in result:
      ic = InferredConfig.from_dict(result['Ok'])
      return ic.device_config, ic.image_config
    else: raise RuntimeError(f"Memory config inference failed: {result.get('Err', 'Unknown error')}")

  def create_project_image(self, project_name: str, image_name: str, image_config: ImageConfig) -> str:
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

  def update_project_image(self, project_name: str, image_name: str, image_config: ImageConfig) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/image/{image_name}',
      json=image_config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image update failed: {result['Err']}")

  def project_image_exists(self, project_name: str, image_name: str) -> bool:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/image/{image_name}'
    )
    return resp.status_code == 200 and 'Ok' in resp.text

  def get_project_image(self, project_name: str, image_name: str) -> ImageConfig:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/image/{image_name}'
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image retrieval failed: {result['Err']}")
    else: return ImageConfig.from_dict(result['Ok'])

  def get_project_images(self, project_name: str) -> List[str]:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/images'
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image retrieval failed: {result['Err']}")
    else: return result['Ok']

  def delete_image(self, project_name: str, image_name: str) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/image/{image_name}/delete'
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image deletion failed: {result['Err']}")

  def create_project(self, project_name: str, config: ProjectConfig, overwrite: bool = False) -> None:
    resp = self._make_request(
      'POST',
      '/create-project',
      params={
        'project_name': project_name,
        'overwrite': str(overwrite).lower()
      },
      json=config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project creation failed: {result['Err']}")

  def project_exists(self, project_name: str) -> bool:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/exists'
    )
    return resp.status_code == 200 and 'Ok' in resp.text and resp.json()['Ok']

  def image_exists(self, project_name: str, image_name: str) -> bool:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/image/{image_name}/exists'
    )
    return resp.status_code == 200 and 'Ok' in resp.text and resp.json()['Ok']

  def rename_project(self, project_name: str, new_name: str) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/rename',
      json=new_name
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project renaming failed: {result['Err']}")

  def delete_project(self, project_name: str) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/delete'
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project deletion failed: {result['Err']}")

  def get_project_config(self, project_name: str) -> ProjectConfig:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/config'
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project config retrieval failed: {result['Err']}")
    else: return ProjectConfig.from_dict(result['Ok'])

  def set_project_config(self, project_name: str, config: ProjectConfig) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/config',
      json=config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project config setting failed: {result['Err']}")
    else: return result['Ok']

  def start_run(self, project_name: str, config: RunConfig) -> int:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/start-run',
      json=config.to_dict()
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Run start failed: {result['Err']}")
    else: return result['Ok']

  def get_run_status(self, project_name: str, run_id: int) -> RunStatus:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/summary'
    )
    result = resp.json()
    return RunSummary.from_dict(result).status

  def stop_run(self, project_name: str, run_id: int) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/run/{run_id}/stop'
    )
    
    if resp.text != 'OK':
      raise RuntimeError(f"Stop run failed: {resp.text}")

  def get_runs(self, project_name: str) -> List[Tuple[int, RunSummary]]:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/runs'
    )
    return [(run_id, RunSummary.from_dict(run)) for (run_id, run) in resp.json()]

  def get_run_stats(self, project_name: str, run_id: int) -> RunStats:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/stats'
    )
    return RunStats.from_dict(resp.json())

  def set_image_symbols(self, project_name: str, image_name: str, symbols: List[Symbol]) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/image/{image_name}/symbols',
      json=[symbol.to_dict() for symbol in symbols]
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Symbol setting failed: {result['Err']}")

  def get_image_symbols(self, project_name: str, image_name: str) -> List[Symbol]:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/image/{image_name}/symbols'
    )
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Symbol retrieval failed: {result['Err']}")
    else: return [Symbol.from_dict(symbol) for symbol in result['Ok']]

  def get_testcases(self, project_name: str, run_id: int) -> List[Testcase]:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/testcases'
    )
    return [Testcase.from_dict(testcase) for testcase in resp.json()]

  def get_testcase_input(self, project_name: str, run_id: int, testcase_id: str) -> TestcaseInput:
    resp = self._make_request(
      'GET',
      f'/project/{project_name}/run/{run_id}/testcase/{testcase_id}/input'
    )
    return TestcaseInput.from_bytes(resp.content)

  def start_debug_session(self, project_name: str, run_id: int, testcase_id: str) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/run/{run_id}/debug-session/{testcase_id}/start'
    )
    
    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Debug session start failed: {result['Err']}")
  
  def send_debug_command(self, project_name: str, run_id: int, testcase_id: str, command: str) -> None:
    resp = self._make_request(
      'POST',
      f'/project/{project_name}/run/{run_id}/debug-session/{testcase_id}/command',
      json=command
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Debug command send failed: {result['Err']}")
    else: return result['Ok']

  def inject_project(self, zip_path: str) -> None:
    if not os.path.exists(zip_path):
      raise FileNotFoundError(f"File not found: {zip_path}")

    with open(zip_path, 'rb') as f:
      zip_data = f.read()

    resp = self._make_request(
      'POST',
      f'/inject-project',
      data=zip_data
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Project injection failed: {result['Err']}")

  def inject_image(self, zip_path: str) -> None:
    if not os.path.exists(zip_path):
      raise FileNotFoundError(f"File not found: {zip_path}")

    with open(zip_path, 'rb') as f:
      zip_data = f.read()

    resp = self._make_request(
      'POST',
      f'/inject-image',
      data=zip_data,
    )

    result = resp.json()
    if isinstance(result, dict) and 'Err' in result:
      raise RuntimeError(f"Image injection failed: {result['Err']}")
