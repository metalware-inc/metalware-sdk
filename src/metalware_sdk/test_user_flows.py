from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.havoc_common_schema import *
from unittest import TestCase, main, skip
import time
import os

def pretty_device_config(device_config: DeviceConfig) -> str:
  result = ""
  result += f"Memory layout:\n"
  for memory in device_config.memory_layout:
    result += f" - {hex(memory.base_addr)} {hex(memory.size)} {memory.memory_type} {memory.file}\n"
    result += f"Entry address: {hex(device_config.entry_address)}\n"
  return result

def get_rom_addr(device_config: DeviceConfig) -> int:
  for memory in device_config.memory_layout:
    if memory.memory_type == MemoryType.ROM:
      return memory.base_addr
  raise Exception("ROM address not found")

HOST_URL = "http://localhost:8080" if os.getenv("HOST_URL") is None else os.getenv("HOST_URL")

class TestHavoc(TestCase):
  def test_alias_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/alias-test.elf")

    device_config, image_config = client.infer_config(file_hash=file_metadata.hash)

    device_config.memory_layout.append(Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM, aliased_to=0x24000000))
    device_config.memory_layout.append(Memory(base_addr=0x24000000, size=0x100000, memory_type=MemoryType.RAM))

    project_config = ProjectConfig(device_config)
    client.create_project("alias-test.tmp", project_config, overwrite=True)

    client.create_project_image(project_name="alias-test.tmp", image_name="default", image_config=image_config)

    client.start_run(project_name="alias-test.tmp", config=RunConfig(image_name="default", dry_run=True))

  def test_zephyr_rom_infer(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.bin")

    device_config, image_config = client.infer_config(file_hash=file_metadata.hash)

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

  def test_zephyr_rom_no_infer(self):
    client = HavocClient(HOST_URL)

    device_config = DeviceConfig(memory_layout=[
       Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
       Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
       Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
    ])

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    # Upload ROM
    upload_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.bin")

    # Create ImageConfig
    raw_image = RawImage(segments=[RawImageSegment(address=0x400000, hash=upload_metadata.hash)])

    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    # Create Run
    client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

  def test_zephyr_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.elf")

    device_config, image_config = client.infer_config(file_hash=file_metadata.hash)

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

  def test_overlapping_regions(self):
    client = HavocClient(HOST_URL)

    device_config = DeviceConfig(memory_layout=[
      Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
      Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x20000500, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO)
    ])

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    upload_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.elf")

    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=upload_metadata.hash))
    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    with self.assertRaises(Exception) as context:
      client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
      self.assertTrue("overlaps" in str(context.exception))

  def test_missing_regions(self):
    client = HavocClient(HOST_URL)

    device_config = DeviceConfig(memory_layout=[
      Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
      Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x22000000, size=0x100000, memory_type=MemoryType.RAM),
    ])

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    upload_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.elf")

    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=upload_metadata.hash))
    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    # Assert exception is thrown
    with self.assertRaises(Exception) as context:
      client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
      self.assertTrue("missing" in str(context.exception))

  def test_undersized_rom(self):
    client = HavocClient(HOST_URL)

    device_config = DeviceConfig(memory_layout=[
       Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
       Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
       Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
    ])

    project_config = ProjectConfig(device_config)
    client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

    upload_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.bin")

    raw_image = RawImage(segments=[RawImageSegment(address=0x400000, hash=upload_metadata.hash)])

    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
    client.create_project_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

    with self.assertRaises(Exception) as context:
      client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
      self.assertTrue("too small" in str(context.exception))

  def test_create_rename_delete_project(self):
    client = HavocClient(HOST_URL)
    # Create project
    client.create_project("dummy.tmp", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)

    if client.project_exists("dummy"): client.delete_project("dummy")
    # Rename project
    client.rename_project(project_name="dummy.tmp", new_name="dummy")

    # Check that project was renamed
    project_config = client.get_project_config("dummy")
    self.assertEqual(len(project_config.device_config.memory_layout), 1)
    self.assertEqual(project_config.device_config.memory_layout[0].base_addr, 0x400000)
    self.assertEqual(project_config.device_config.memory_layout[0].size, 0x100000)
    self.assertEqual(project_config.device_config.memory_layout[0].memory_type, MemoryType.ROM)

    # Delete project
    client.delete_project("dummy")

    # Check that project was deleted
    with self.assertRaises(Exception) as context:
      client.get_project_config("dummy")

  def test_set_project_config(self):
    client = HavocClient(HOST_URL)

    try: client.delete_project("dummy-2")
    except Exception as e: pass

    memory_layout = [
      Memory(base_addr=0x500000, size=0x100000, memory_type=MemoryType.ROM),
      Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
    ]

    client.create_project("dummy-2", ProjectConfig(DeviceConfig(memory_layout=memory_layout)))

    # Check that project config was set
    project_config = client.get_project_config("dummy-2")
    self.assertEqual(len(project_config.device_config.memory_layout), 3)
    self.assertEqual(project_config.device_config.memory_layout[0].base_addr, 0x500000)
    self.assertEqual(project_config.device_config.memory_layout[0].size, 0x100000)
    self.assertEqual(project_config.device_config.memory_layout[0].memory_type, MemoryType.ROM)

    # Set project config
    memory_layout[0].base_addr = 0x400000
    memory_layout[0].size = 0x100002
    client.set_project_config("dummy-2", ProjectConfig(DeviceConfig(memory_layout=memory_layout)))

    # Check that project config was set
    project_config = client.get_project_config("dummy-2")
    self.assertEqual(len(project_config.device_config.memory_layout), 3)
    self.assertEqual(project_config.device_config.memory_layout[0].base_addr, 0x400000)
    self.assertEqual(project_config.device_config.memory_layout[0].size, 0x100002)
    self.assertEqual(project_config.device_config.memory_layout[0].memory_type, MemoryType.ROM)

    # Delete project
    client.delete_project("dummy-2")

    # Check that project was deleted
    with self.assertRaises(Exception) as context:
      client.get_project_config("dummy-2")

  def test_multi_segment_raw_image(self):
    client = HavocClient(HOST_URL)

    # Create project
    device_config = DeviceConfig(memory_layout=[
      Memory(base_addr=0x8000000, size=0x8000, memory_type=MemoryType.ROM),
      Memory(base_addr=0x8008000, size=0x8000, memory_type=MemoryType.ROM),
      Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
    ])

    client.create_project("multi-segment-raw-image.tmp", ProjectConfig(device_config), overwrite=True)

    # Upload ROM
    bootloader = client.upload_file("ci-resources/test-binaries/simple-bootloader/bootloader.bin")
    app = client.upload_file("ci-resources/test-binaries/simple-bootloader/app.bin")

    # Create image
    raw_image = RawImage(segments=[
      RawImageSegment(address=0x8000000, hash=bootloader.hash),
      RawImageSegment(address=0x8008000, hash=app.hash)
    ])

    image_config = ImageConfig(entry_address=0x8000000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
    client.create_project_image(project_name="multi-segment-raw-image.tmp", image_name="default", image_config=image_config)

    # Start run
    client.start_run(project_name="multi-segment-raw-image.tmp", config=RunConfig(image_name="default", dry_run=True))

  def test_set_get_image_symbols(self):
    client = HavocClient(HOST_URL)

    # Create project
    client.create_project("dummy.tmp", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)

    # Upload elf
    file_metadata = client.upload_file("ci-resources/test-binaries/alias-test.elf")

    # Create image
    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash))
    client.create_project_image(project_name="dummy.tmp", image_name="default", image_config=image_config)

    # Set image symbols
    client.set_image_symbols(project_name="dummy.tmp", image_name="default", symbols=[Symbol(name="symbol1", address=0x1000, size=0x4), Symbol(name="symbol2", address=0x2000, size=0x4)])

    # Get image symbols
    symbols = client.get_image_symbols(project_name="dummy.tmp", image_name="default")
    self.assertEqual(len(symbols), 2)
    self.assertEqual(symbols[0].name, "symbol1")
    self.assertEqual(symbols[0].address, 0x1000)
    self.assertEqual(symbols[0].size, 0x4)
    self.assertEqual(symbols[1].name, "symbol2")
    self.assertEqual(symbols[1].address, 0x2000)
    self.assertEqual(symbols[1].size, 0x4)

    # Set image symbols again
    client.set_image_symbols(project_name="dummy.tmp", image_name="default", symbols=[Symbol(name="symbol1", address=0x1004, size=0x1), Symbol(name="symbol2", address=0x2004, size=0x1)])

    # Get image symbols again
    symbols = client.get_image_symbols(project_name="dummy.tmp", image_name="default")
    self.assertEqual(len(symbols), 2)
    self.assertEqual(symbols[0].name, "symbol1")
    self.assertEqual(symbols[0].address, 0x1004)
    self.assertEqual(symbols[0].size, 0x1)
    self.assertEqual(symbols[1].name, "symbol2")
    self.assertEqual(symbols[1].address, 0x2004)
    self.assertEqual(symbols[1].size, 0x1)

  def test_get_image_symbols_new_image(self):
    client = HavocClient(HOST_URL)

    # Create project
    client.create_project("dummy.tmp", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)

    # Upload elf
    file_metadata = client.upload_file("ci-resources/test-binaries/alias-test.elf")

    # Create image
    try: client.delete_image(project_name="dummy.tmp", image_name="default")
    except Exception as e: pass

    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash))
    client.create_project_image(project_name="dummy.tmp", image_name="default", image_config=image_config)

    # Get image symbols
    symbols = client.get_image_symbols(project_name="dummy.tmp", image_name="default")
    self.assertEqual(len(symbols), 5)

  def test_create_project_overwrite_fail(self):
    client = HavocClient(HOST_URL)
    with self.assertRaises(Exception) as context:
      client.create_project("dummy", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)
    self.assertTrue("when overwriting" in str(context.exception))

  def test_create_project_same_name_fail(self):
    client = HavocClient(HOST_URL)
    with self.assertRaises(Exception) as context:
      client.create_project("dummyxxl", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=False)
      client.create_project("dummyxxl", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=False)
    self.assertTrue("already taken" in str(context.exception))

  def test_create_get_project_image(self):
    client = HavocClient(HOST_URL)

    # Create project
    client.create_project("dummy.tmp", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)

    # Get project images again
    images = client.get_project_images(project_name="dummy.tmp")
    self.assertEqual(len(images), 0)

    # Create image
    file_metadata = client.upload_file("ci-resources/test-binaries/alias-test.elf")
    client.create_project_image(project_name="dummy.tmp", image_name="default", image_config=ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash)))

    # Get project images
    images = client.get_project_images(project_name="dummy.tmp")
    self.assertEqual(len(images), 1)
    self.assertEqual(images[0], "default")

    # Get image config
    image = client.get_project_image(project_name="dummy.tmp", image_name=images[0])
    self.assertEqual(image.image_arch, ImageArch.CORTEX_M)
    self.assertEqual(image.image_format.elf, file_metadata.hash)

  def test_update_project_image(self):
    client = HavocClient(HOST_URL)

    # Create project
    client.create_project("dummy.tmp", ProjectConfig(DeviceConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)])), overwrite=True)

    # Upload elf
    file_metadata = client.upload_file("ci-resources/test-binaries/alias-test.elf")

    # Create image
    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash))
    client.create_project_image(project_name="dummy.tmp", image_name="default", image_config=image_config)

    # Get image
    image = client.get_project_image(project_name="dummy.tmp", image_name="default")
    self.assertEqual(image.image_arch, ImageArch.CORTEX_M)
    self.assertEqual(image.image_format.elf, file_metadata.hash)
    self.assertEqual(len(image.patches), 0)

    # Upload another elf
    file_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.elf")

    # Update image
    image_config = ImageConfig(entry_address=0x400000, image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash), patches=[Patch(address=0x20000000, patch_type=PatchType.NOP)])
    client.update_project_image(project_name="dummy.tmp", image_name="default", image_config=image_config)

    # Get image config again
    image = client.get_project_image(project_name="dummy.tmp", image_name="default")
    self.assertEqual(image.image_arch, ImageArch.CORTEX_M)
    self.assertEqual(image.image_format.elf, file_metadata.hash)
    self.assertEqual(len(image.patches), 1)
    self.assertEqual(image.patches[0].address, 0x20000000)
    self.assertEqual(image.patches[0].patch_type, PatchType.NOP)

  def infer_and_run(self, file_path: str, manual_entry_address: int = None, manual_memories: List[Memory] = [], dry_run: bool = True):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file(file_path)
    device_config, image_config = client.infer_config(file_hash=file_metadata.hash)
    # Remove all memories that share base addres with manual memories
    device_config.memory_layout = [memory for memory in device_config.memory_layout if memory.base_addr not in [memory.base_addr for memory in manual_memories]]
    for memory in manual_memories: device_config.memory_layout.append(memory)
    project_config = ProjectConfig(device_config)
    project_name = file_path.split("/")[-1].split(".")[0] + (".tmp" if dry_run else "")
    client.create_project(project_name, project_config, overwrite=dry_run)
    if manual_entry_address is not None: image_config.entry_address = manual_entry_address
    client.create_project_image(project_name=project_name, image_name="default", image_config=image_config)
    client.start_run(project_name=project_name, config=RunConfig(image_name="default", dry_run=dry_run))

  def test_portenta_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/portenta_STM32H747AII6_CM7.elf")

  def test_knickerbocker_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/knickerbocker.elf")

  def test_floormat_infer(self):
    self.infer_and_run("ci-resources/test-binaries/floormat.elf")

  def test_adi_ble_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/ADI_periph_max32655.elf")

  def test_p2im_console_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/p2im.console.elf", manual_entry_address=0x0)

  def test_arducopter_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/arducopter.elf")

  def test_silabs_bt_soc_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/silabs_bt_soc_blinky_3.out")

  def test_simple_rom_unaligned_isr(self):
    self.infer_and_run("ci-resources/test-binaries/simple-rom-unaligned-isr-table.elf")

  @skip("Skipping due to memory overlap")
  def test_hsm_host_elf_infer(self):
    manual_memories = [
      Memory(base_addr=0x0, size=0x100000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x20010000, size=0x10000, memory_type=MemoryType.RAM),
      Memory(base_addr=0x20100000, size=0x100000, memory_type=MemoryType.RAM),
    ]
    self.infer_and_run("ci-resources/test-binaries/hsm_host_test_sb_hsm_pic32cz_ca90.X.debug.elf", manual_memories=manual_memories)

  def test_px4_elf_infer(self):
    self.infer_and_run("ci-resources/test-binaries/px4_fmu-v5_default.elf", manual_entry_address=0x8008000)

  def test_get_testcases(self):
    client = HavocClient(HOST_URL)
    # stop run if it exists
    try: client.stop_run(project_name="px4_fmu-v5_default", run_id=1)
    except Exception as e: pass

    # delete project if it exists
    try: client.delete_project("px4_fmu-v5_default")
    except Exception as e: pass

    self.infer_and_run("ci-resources/test-binaries/px4_fmu-v5_default.elf", manual_entry_address=0x8008000, dry_run=False)

    print("Waiting for testcases to be generated...")
    found = False
    for _ in range(60):
      testcases = client.get_testcases(project_name="px4_fmu-v5_default", run_id=1)
      time.sleep(1)
      if len(testcases) > 0:
        print("input id =", testcases[0].input_id)
        input = client.get_testcase_input(project_name="px4_fmu-v5_default", run_id=1, testcase_id=testcases[0].input_id)
        print(input)
        found = True
        break

    # Stop run
    client.stop_run(project_name="px4_fmu-v5_default", run_id=1)
    if not found: raise Exception("No testcases found")

  def delete_project(self, project_name: str, run_id: int = 1):
    client = HavocClient(HOST_URL)
    try: client.stop_run(project_name=project_name, run_id=run_id)
    except Exception as e: pass
    try: client.delete_project(project_name)
    except Exception as e: pass

  def test_executable_ram_binary_ok(self):
    """
    This test makes sure that a binary that executes from RAM crashes with the expected flag (0xdeadbeef).
    This proves RAM execution works when enabled.
    """
    client = HavocClient(HOST_URL)
    self.delete_project("executable_ram")
    self.infer_and_run("ci-resources/test-binaries/executable_ram.elf", manual_memories=[Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM, executable=True)], dry_run=False)
    print("Waiting for testcases to be generated...")
    found_flag = False
    for _ in range(60):
      if found_flag: break
      testcases = client.get_testcases(project_name="executable_ram", run_id=1)
      time.sleep(1)
      for testcase in testcases:
        if '0xdeadbeef' in testcase.exit_reason:
          print(f"Found testcase containing flag: {testcase.exit_reason}")
          found_flag = True
          break
    client.stop_run(project_name="executable_ram", run_id=1)
    if not found_flag: raise Exception("Could not find testcase containing flag")

  def test_executable_ram_binary_fail(self):
    """
    This test makes sure that a binary that executes from RAM crashes with the expected flag (0x20000000).
    This proves RAM execution fails as expected when NOT enabled.
    """
    client = HavocClient(HOST_URL)
    self.delete_project("executable_ram")
    self.infer_and_run("ci-resources/test-binaries/executable_ram.elf", dry_run=False)
    print("Waiting for testcases to be generated...")
    found_flag = False
    for _ in range(60):
      if found_flag: break
      testcases = client.get_testcases(project_name="executable_ram", run_id=1)
      time.sleep(1)
      for testcase in testcases:
        if '0x20000000' in testcase.exit_reason:
          print(f"Found testcase containing flag: {testcase.exit_reason}")
          found_flag = True
          break
    client.stop_run(project_name="executable_ram", run_id=1)
    if not found_flag: raise Exception("Could not find testcase containing flag")

if __name__ == "__main__":
  main()
