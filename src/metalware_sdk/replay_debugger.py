import json

from metalware_sdk.havoc_client import HavocClient


class ReplayDebugger:
  def __init__(self, client: HavocClient, project_name: str, run_id: int, testcase_id: str):
    self._client = client
    self._project_name = project_name
    self._run_id = run_id
    self._testcase_id = testcase_id

    self._client.start_debug_session(self._project_name, self._run_id, self._testcase_id)

  def _send_command(self, command: dict):
    result = self._client.send_debug_command(self._project_name, self._run_id, self._testcase_id, json.dumps(command))
    return json.loads(result)

  def run(self) -> str:
    res = self._send_command({"c": "run"})
    if 'data' in res and 'exit_reason' in res['data']:
      return res['data']['exit_reason']
    else:
      raise RuntimeError(f"Failed to run: {res}")

  def add_breakpoint(self, address: int):
    self._send_command({"c": "add_breakpoint", "address": address})

  def remove_breakpoint(self, address: int):
    self._send_command({"c": "remove_breakpoint", "address": address})

  def add_watchpoint(self, address: int, watch_type: str):
    self._send_command({"c": "add_watchpoint", "address": address, "watch_type": watch_type})

  def remove_watchpoint(self, address: int, watch_type: str):
    self._send_command({"c": "remove_watchpoint", "address": address, "watch_type": watch_type})

  def step(self) -> str:
    res = self._send_command({"c": "step"})
    if 'data' in res and 'exit_reason' in res['data']:
      return res['data']['exit_reason']
    else:
      raise RuntimeError(f"Failed to step: {res}")

  def step_back(self) -> str:
    res = self._send_command({"c": "step_back"})
    if 'data' in res and 'exit_reason' in res['data']:
      return res['data']['exit_reason']
    else:
      raise RuntimeError(f"Failed to step back: {res}")

  def state(self) -> dict:
    result = self._send_command({"c": "state"})
    if 'data' in result:
      return result['data']
    else:
      raise RuntimeError(f"Failed to get state: {result}")

  def read_register(self, register_name: str) -> int:
    result = self._send_command({"c": "read_reg", "reg_name": register_name})
    if 'data' in result and 'value' in result['data']:
      return result['data']['value']
    else:
      raise RuntimeError(f"Failed to get register: {result}")

  def list_registers(self) -> dict:
    result = self._send_command({"c": "list_regs"})
    if 'data' in result and 'registers' in result['data']:
      return result['data']['registers']
    else:
      raise RuntimeError(f"Failed to get registers: {result}")

  def read_memory(self, address: int, size: int) -> bytes:
    result = self._send_command({"c": "read_mem", "address": address, "size": size})
    if 'data' in result:
      return result['data']
    else:
      raise RuntimeError(f"Failed to get memory: {result}")

  def write_memory(self, address: int, data: bytes) -> None:
    self._send_command({"c": "write_mem", "address": address, "data": data})

  def disassemble(self, count: int) -> list[str]:
    result = self._send_command({"c": "disassemble", "count": count})
    if 'data' in result and 'disassembly' in result['data']:
      return result['data']['disassembly']
    else:
      raise RuntimeError(f"Failed to get disassembly: {result}")

  def list_registers(self) -> dict:
    result = self._send_command({"c": "list_regs"})
    if 'data' in result and 'registers' in result['data']:
      return result['data']['registers']
    else:
      raise RuntimeError(f"Failed to get registers: {result}")

  def list_watchpoints(self) -> list[int]:
    result = self._send_command({"c": "list_watchpoints"})
    if 'data' in result and 'watchpoints' in result['data']:
      return result['data']['watchpoints']
    else:
      raise RuntimeError(f"Failed to get watchpoints: {result}")

  def list_breakpoints(self) -> list[int]:
    result = self._send_command({"c": "list_breakpoints"})
    if 'data' in result and 'breakpoints' in result['data']:
      return result['data']['breakpoints']
    else:
      raise RuntimeError(f"Failed to get breakpoints: {result}")

  def backtrace(self) -> list[int]:
    result = self._send_command({"c": "backtrace"})
    if 'data' in result and 'backtrace' in result['data']:
      return result['data']['backtrace']
    else:
      raise RuntimeError(f"Failed to get backtrace: {result}")