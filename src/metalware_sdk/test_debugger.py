from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.replay_debugger import ReplayDebugger, WatchType
import time
import os
import unittest

HOST_URL = "http://localhost:8080" if os.getenv("HOST_URL") is None else os.getenv("HOST_URL")
client = HavocClient(base_url=HOST_URL)

class TestDebugger(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.inject_zephyr10064_project()

  def inject_zephyr10064_project(): # one-off setup
    print("Injecting zephyr10064 project...")
    if client.project_exists("zephyr10064.clone"): client.delete_project("zephyr10064.clone")
    client.inject_project("ci-resources/test-projects/zephyr10064-project.zip")
    client.inject_image("ci-resources/test-projects/zephyr10064-image.zip")

  def test_step(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

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

  def test_breakpoint(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

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
    assert pc == 0x0, f"PC: {hex(pc)}"

    # Test rewind.
    debugger.rewind()

    state = debugger.state()
    assert state['pc'] == 0x402dcc, f"PC: {hex(state['pc'])}"
    assert state['icount'] == 0, f"ICount: {state['icount']}"


  def test_write_watchpoint(self):
    # The memory at 0x20005ac4 is written at the following addresses: 0x40db3e, 0x40db78, 0x402c72
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

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
    assert state['pc'] == 0x0, f"PC: {hex(state['pc'])}"

  def test_read_watchpoint(self):
    # Test read_watchpoint. The memory at 0x20006400 is read at the following addresses: 0x402dba, 0x402dba, 0x4029ce, 0x402dba, 0x4029ce
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

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
    assert state['pc'] == 0x0, f"PC: {hex(state['pc'])}"

  def test_readwrite_watchpoint(self):
    # Test readwrite_watchpoint. The memory at 0x200063f4 is:
    # - WRITTEN at 0x40db78
    # - WRITTEN at 0x40db3e
    # - READ    at 0x40db6a
    # - WRITTEN at 0x40dae8
    # - READ    at 0x40dafc
    # - WRITTEN at 0x40dae8
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

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
    assert state['pc'] == 0x0, f"PC: {hex(state['pc'])}"

  def test_write_register_branch_target(self):
    # Rewrites the branch target r3 in last instruction.
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40d4bc)
    debugger.run()

    assert debugger.read_register("pc") == 0x40d4bc, f"PC: {hex(debugger.read_register('pc'))}"

    debugger.write_register("r3", 0xdeadbeee)
    exit_reason = debugger.run()

    assert exit_reason == "invalid_jump", f"Exit reason: {exit_reason}"
    assert debugger.read_register("pc") == 0xdeadbeee, f"PC: {hex(debugger.read_register('pc'))}"

  def test_write_register_comparison(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40dae2)
    debugger.run()

    assert debugger.read_register("pc") == 0x40dae2, f"PC: {hex(debugger.read_register('pc'))}"
    # 0x40dae2  cmp r2,r1     ; r1 = 0x2000a1e7, r2 = 0x2000a1e5
    # 0x40dae4  bne 0x40dada  ; in original trace, this branch is taken.
    assert debugger.read_register("r1") == 0x2000a1ff, f"R1: {hex(debugger.read_register('r1'))}"
    assert debugger.read_register("r2") == 0x2000a1ff, f"R2: {hex(debugger.read_register('r2'))}"

    # Make r2 NOT equal to r1 so that branch is taken.
    debugger.write_register("r2", 0x2000a1e7)

    debugger.step()
    debugger.step()

    assert debugger.read_register("pc") == 0x40dada, f"PC: {hex(debugger.read_register('pc'))}"

  def test_write_register_invalid(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    try:
      debugger.write_register("r19x", 0xdeadbeee)
    except RuntimeError as e:
      assert "Unknown register" in str(e)
    else: assert False, "Expected RuntimeError"

  def test_decompile_range(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x00402990)
    debugger.run()

    debugger.step()
    debugger.step()

    current_pc = debugger.read_register("pc")

    for _ in range(14):
      start_time = time.monotonic()
      debugger.step()
      debugger.print_asm()

    for _ in range(4):
      debugger.step_back()
      debugger.print_asm()

    print("time to disassemble: ", time.monotonic() - start_time)

  def test_read_memory(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40db78)
    debugger.run()

    assert debugger.read_memory(0x20005c08, 4) == b'\x00\x00\x00\x00', f"Memory: {debugger.read_memory(0x20005c08, 4)}"
    debugger.step()
    assert debugger.read_memory(0x20005c08, 4) == b'\xaa\xaa\xaa\xaa', f"Memory: {debugger.read_memory(0x20005c08, 4)}"

    debugger.remove_breakpoint(0x40db78)
    debugger.add_watchpoint(0x20002738, WatchType.WRITE)
    debugger.run()
    debugger.run()
    debugger.step_back()

    assert debugger.read_memory(0x20002738, 4) != 0x80000000.to_bytes(4, "little"), f"Memory: {debugger.read_memory(0x20002738, 4)}"
    debugger.step()
    assert debugger.read_memory(0x20002738, 4) == 0x80000000.to_bytes(4, "little"), f"Memory: {debugger.read_memory(0x20002738, 4)}"

  def test_read_memory_mmio(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40db78)
    debugger.run()

    try:
      debugger.read_memory(0x400e1858, 4)
    except RuntimeError as e:
      assert "Failed to read memory at 0x400e1858" in str(e), f"Actual error: {e}"
    else: assert False, "Expected RuntimeError"

  @unittest.skip("Skipping backtrace test")
  def test_backtrace(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40db78)
    debugger.run()

    debugger.print_backtrace()
    assert debugger.backtrace() == [0x40db78], f"Backtrace: {debugger.backtrace()}"

  def test_ram_write(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")
    debugger.add_breakpoint(0x40d4bc)
    debugger.run()

    debugger.remove_breakpoint(0x40d4bc)
    for _ in range(6): debugger.step_back()

    pc = debugger.read_register("pc")
    assert pc == 0x40d4b0, f"PC: {hex(pc)}"

    # Overwrite attacker controlled memory to jump to 0xdeadbeef.
    debugger.write_memory(0x20002510, 0xdeadbeef.to_bytes(4, "little"))
    assert debugger.read_memory(0x20002510, 4) == 0xdeadbeef.to_bytes(4, "little"), f"Memory: {debugger.read_memory(0x20002510, 4)}"
    debugger.run()

    assert debugger.read_register("pc") == 0xdeadbeee, f"PC: {hex(debugger.read_register('pc'))}"

  def test_mmio_write(self):
    debugger = ReplayDebugger(client, "zephyr10064.clone", 5, "crash_0x0_unknown")

    # assert that exception is thrown containing "Cannot write to IO memory at 0x400e1858"
    try:
      debugger.write_memory(0x400e1858, 0xdeadbeef.to_bytes(4, "little"))
    except RuntimeError as e:
      assert "Cannot write to IO memory at 0x400e1858" in str(e)
    else: assert False, "Expected RuntimeError"

if __name__ == "__main__":
  unittest.main()
