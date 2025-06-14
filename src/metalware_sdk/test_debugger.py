from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.replay_debugger import ReplayDebugger

client = HavocClient(base_url="http://localhost:8080")

# TODO
# client.inject_project("test_projects/zephyr-10064.zip") # DEV-ONLY
# testcases = client.list_testcases("cve2020-10064-june13", 1)

# assert "0x402dbb_0x3e8_jump_invalid" in testcases, f"Testcase not found: {testcases}"

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
assert "ExecViolation" in exit_reason, f"Exit reason: {exit_reason}"
# Test read_register.
pc = debugger.read_register('pc')
assert pc == 0x2000, f"PC: {hex(pc)}"

# TODO: add_watchpoint, list_watchpoints, remove_watchpoint, write_memory, read_memory, disassemble, backtrace.
# TODO: test write_register.