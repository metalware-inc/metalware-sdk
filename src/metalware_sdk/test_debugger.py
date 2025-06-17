from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.replay_debugger import ReplayDebugger, WatchType
import time

client = HavocClient(base_url="http://localhost:8080")

# TODO
# client.inject_project("test_projects/zephyr-10064.zip") # DEV-ONLY
# testcases = client.list_testcases("cve2020-10064-june13", 1)

# assert "0x402dbb_0x3e8_jump_invalid" in testcases, f"Testcase not found: {testcases}"

def test_step():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")

  # Test step.
  state = debugger.state()
  assert state['pc'] == 0x402dcc, f"PC: {hex(state['pc'])}" # Reset_Handler
  assert state['icount'] == 0, f"ICount: {state['icount']}"

  debugger.step()

  state = debugger.state()
  assert state['pc'] == 0x402dce, f"PC: {hex(state['pc'])}" # Reset_Handler
  assert state['icount'] == 1, f"ICount: {state['icount']}"

  # Test step_back.
  for _ in range(100): debugger.step()
  for _ in range(100): debugger.step_back()

  state = debugger.state()
  assert state['pc'] == 0x402dce, f"PC: {hex(state['pc'])}" # Reset_Handler
  assert state['icount'] == 1, f"ICount: {state['icount']}"

def test_breakpoint():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")

  # Test add_breakpoint, list_breakpoints.
  debugger.add_breakpoint(0x402988)
  assert debugger.list_breakpoints() == [0x402988], f"Breakpoints: {debugger.list_breakpoints()}"

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x402988, f"PC: {hex(state['pc'])}"
  last_icount = state['icount']

  exit_reason = debugger.step()

  state = debugger.state()
  assert state['pc'] == 0x40298a, f"PC: {hex(state['pc'])}"

  # Continue until breakpoint (0x402988 occurs several times).
  exit_reason = debugger.run()
  assert exit_reason == "breakpoint", f"Exit reason: {exit_reason}"
  state = debugger.state()
  assert state['icount'] > last_icount + 50, f"ICount: {state['icount']} Last ICount: {last_icount}"

  # Test remove_breakpoint.
  debugger.remove_breakpoint(0x402988)
  assert debugger.list_breakpoints() == [], f"Breakpoints: {debugger.list_breakpoints()}"

  # Continue to crashpoint (end of program).
  exit_reason = debugger.run()
  assert "invalid_jump" in exit_reason, f"Exit reason: {exit_reason}"
  # Test read_register.
  pc = debugger.read_register('pc')
  assert pc == 0x2000, f"PC: {hex(pc)}"

  # Test rewind.
  debugger.rewind()

  state = debugger.state()
  assert state['pc'] == 0x402dcc, f"PC: {hex(state['pc'])}"
  assert state['icount'] == 0, f"ICount: {state['icount']}"


def test_write_watchpoint():
  # The memory at 0x20005ac4 is written at the following addresses: 0x40db3e, 0x40db78, 0x402c72
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")

  debugger.add_watchpoint(0x20005ac4, WatchType.WRITE)

  # Test list_watchpoints.
  assert debugger.list_watchpoints() == [(0x20005ac4, WatchType.WRITE)], f"Watchpoints: {debugger.list_watchpoints()}"

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x40db3e, f"PC: {hex(state['pc'])}"

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x40db78, f"PC: {hex(state['pc'])}"


  debugger.remove_watchpoint(0x20005ac4, WatchType.WRITE)
  assert debugger.list_watchpoints() == [], f"Watchpoints: {debugger.list_watchpoints()}"

  # Should now hit end of program instead of stopping at 0x402c72
  exit_reason = debugger.run()
  assert "invalid_jump" in exit_reason, f"Exit reason: {exit_reason}"
  state = debugger.state()
  assert state['pc'] == 0x2000, f"PC: {hex(state['pc'])}"

def test_read_watchpoint():
  # Test read_watchpoint. The memory at 0x20006400 is read at the following addresses: 0x402dba, 0x402dba, 0x4029ce, 0x402dba, 0x4029ce
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")

  debugger.add_watchpoint(0x20006400, WatchType.READ)

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x402dba, f"PC: {hex(state['pc'])}"

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x402dba, f"PC: {hex(state['pc'])}"

  # Should do nothing.
  debugger.remove_watchpoint(0x20006400, WatchType.WRITE)

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x4029ce, f"PC: {hex(state['pc'])}"

  debugger.run()

  state = debugger.state()
  assert state['pc'] == 0x402dba, f"PC: {hex(state['pc'])}"

  # Remove watchpoint. Should now hit end of program instead of stopping at 0x4029ce.
  debugger.remove_watchpoint(0x20006400, WatchType.READ)
  assert debugger.list_watchpoints() == [], f"Watchpoints: {debugger.list_watchpoints()}"

  exit_reason = debugger.run()
  assert "invalid_jump" in exit_reason, f"Exit reason: {exit_reason}"
  state = debugger.state()
  assert state['pc'] == 0x2000, f"PC: {hex(state['pc'])}"

def test_readwrite_watchpoint():
  # Test readwrite_watchpoint. The memory at 0x200063f4 is:
  # - WRITTEN at 0x40db78
  # - WRITTEN at 0x40db3e
  # - READ    at 0x40db6a
  # - WRITTEN at 0x40dae8
  # - READ    at 0x40dafc
  # - WRITTEN at 0x40dae8
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")

  debugger.add_watchpoint(0x200063f4, WatchType.READ)
  debugger.add_watchpoint(0x200063f4, WatchType.WRITE)
  exit_reason = debugger.run()
  state = debugger.state()

  assert state['pc'] == 0x40db78, f"PC: {hex(state['pc'])}"
  assert exit_reason == "write_watch", f"Exit reason: {exit_reason}"

  exit_reason = debugger.run()
  state = debugger.state()
  assert state['pc'] == 0x40db3e, f"PC: {hex(state['pc'])}"
  assert exit_reason == "write_watch", f"Exit reason: {exit_reason}"

  exit_reason = debugger.run()
  state = debugger.state()
  assert state['pc'] == 0x40db6a, f"PC: {hex(state['pc'])}"
  assert exit_reason == "read_watch", f"Exit reason: {exit_reason}"

  exit_reason = debugger.run()
  state = debugger.state()
  assert state['pc'] == 0x40dae8, f"PC: {hex(state['pc'])}"
  assert exit_reason == "write_watch", f"Exit reason: {exit_reason}"

  assert len(debugger.list_watchpoints()) == 2, f"Watchpoints: {debugger.list_watchpoints()}"
  assert debugger.list_watchpoints()[0] == (0x200063f4, WatchType.READ), f"Watchpoints: {debugger.list_watchpoints()}"
  assert debugger.list_watchpoints()[1] == (0x200063f4, WatchType.WRITE), f"Watchpoints: {debugger.list_watchpoints()}"

  debugger.remove_watchpoint(0x200063f4, WatchType.WRITE)

  # Remove the two should do nothing.
  assert len(debugger.list_watchpoints()) == 1, f"Watchpoints: {debugger.list_watchpoints()}"
  assert debugger.list_watchpoints()[0] == (0x200063f4, WatchType.READ), f"Watchpoints: {debugger.list_watchpoints()}"

  exit_reason = debugger.run()
  state = debugger.state()
  assert state['pc'] == 0x40dafc, f"PC: {hex(state['pc'])}"
  assert exit_reason == "read_watch", f"Exit reason: {exit_reason}"

  debugger.remove_watchpoint(0x200063f4, WatchType.READ)
  assert debugger.list_watchpoints() == [], f"Watchpoints: {debugger.list_watchpoints()}"

  exit_reason = debugger.run()
  assert "invalid_jump" in exit_reason, f"Exit reason: {exit_reason}"
  state = debugger.state()
  assert state['pc'] == 0x2000, f"PC: {hex(state['pc'])}"

def test_write_register_branch_target():
  # Rewrites the branch target r3 in last instruction.
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x40d4bc)
  debugger.run()

  assert debugger.read_register("pc") == 0x40d4bc, f"PC: {hex(debugger.read_register('pc'))}"

  debugger.write_register("r3", 0xdeadbeee)
  exit_reason = debugger.run()

  assert exit_reason == "invalid_jump", f"Exit reason: {exit_reason}"
  assert debugger.read_register("pc") == 0xdeadbeee, f"PC: {hex(debugger.read_register('pc'))}"

def test_write_register_comparison():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x40dae2)
  debugger.run()

  assert debugger.read_register("pc") == 0x40dae2, f"PC: {hex(debugger.read_register('pc'))}"
  # 0x40dae2  cmp r2,r1     ; r1 = 0x2000a1e7, r2 = 0x2000a1e5
  # 0x40dae4  bne 0x40dada  ; in original trace, this branch is taken.
  assert debugger.read_register("r1") == 0x2000a1e7, f"R1: {hex(debugger.read_register('r1'))}"
  assert debugger.read_register("r2") == 0x2000a1e5, f"R2: {hex(debugger.read_register('r2'))}"

  # Make r2 equal to r1 so that branch is not taken.
  debugger.write_register("r2", 0x2000a1e7)

  debugger.step()
  debugger.step()

  assert debugger.read_register("pc") == 0x40dae6, f"PC: {hex(debugger.read_register('pc'))}"

def test_write_register_invalid():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  try:
    debugger.write_register("r19x", 0xdeadbeee)
  except RuntimeError as e:
    assert "Unknown register" in str(e)
  else: assert False, "Expected RuntimeError"

def test_decompile_range():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x00402990)
  debugger.run()

  debugger.step()
  debugger.step()
  print(hex(debugger.read_register("pc")))

  current_pc = debugger.read_register("pc")

  for _ in range(14):
    start_time = time.monotonic()
    debugger.step()
    debugger.print_asm()
    print(hex(debugger.read_register("pc")))

  for _ in range(4):
    debugger.step_back()
    print(hex(debugger.read_register("pc")))
    debugger.print_asm()

  print("time to disassemble: ", time.monotonic() - start_time)

def test_read_memory():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x40db78)
  debugger.run()

  assert debugger.read_memory(0x20005c08, 4) == [0x00, 0x00, 0x00, 0x00], f"Memory: {debugger.read_memory(0x20005c08, 4)}"
  debugger.step()
  assert debugger.read_memory(0x20005c08, 4) == [0xaa, 0xaa, 0xaa, 0xaa], f"Memory: {debugger.read_memory(0x20005c08, 4)}"

  debugger.remove_breakpoint(0x40db78)
  debugger.add_breakpoint(0x40dade)
  debugger.run()

  assert debugger.read_memory(0x2000a1e7, 1) != [0xe4], f"Memory: {debugger.read_memory(0x2000a1e7, 1)}"
  debugger.step()
  assert debugger.read_memory(0x2000a1e7, 1) == [0xe4], f"Memory: {debugger.read_memory(0x2000a1e7, 1)}"

def test_read_memory_mmio():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x40db78)
  debugger.run()

  assert debugger.read_memory(0x400e1858, 4) == None, f"Memory: {debugger.read_memory(0x400e1858, 4)}"

def test_backtrace():
  debugger = ReplayDebugger(client, "cve2020-10064-june13", 1, "0x402dbb_0x2000_jump_invalid")
  debugger.add_breakpoint(0x40db78)
  debugger.run()

  debugger.print_backtrace()
  assert debugger.backtrace() == [0x40db78], f"Backtrace: {debugger.backtrace()}"


# TODO: write_memory, backtrace.
test_step()
test_breakpoint()
test_write_watchpoint()
test_read_watchpoint()
test_readwrite_watchpoint()
test_write_register_branch_target()
test_write_register_comparison()
test_write_register_invalid()
test_decompile_range()
test_read_memory()
test_read_memory_mmio()
# test_backtrace()