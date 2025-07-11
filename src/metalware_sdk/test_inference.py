from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.havoc_common_schema import DeviceConfig, Memory, MemoryType
import unittest
import os

HOST_URL = "http://localhost:8080" if os.getenv("HOST_URL") is None else os.getenv("HOST_URL")

class TestInference(unittest.TestCase):
  def test_mismatching_file_and_memsizes_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/mismatching_file_mem_sizes.elf")

    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 3)
    self.assertEqual(device_config.memory_layout[0].base_addr, 0x0)
    self.assertEqual(device_config.memory_layout[0].size, 0x14e18)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(len(device_config.memory_layout[0].file.segments), 3)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x8000)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x143e4)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x20010)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0x9d0)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x143f0)

    self.assertEqual(device_config.memory_layout[0].file.segments[2].file_offset, 0x21970)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].size, 0x58)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].memory_offset, 0x14dc0)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[1].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[1].file.segments), 2)

    self.assertEqual(device_config.memory_layout[1].file.segments[0].file_offset, 0x20010)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].size, 0x9d0)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].memory_offset, 0x10)

    self.assertEqual(device_config.memory_layout[1].file.segments[1].file_offset, 0x21970)
    self.assertEqual(device_config.memory_layout[1].file.segments[1].size, 0x58)
    self.assertEqual(device_config.memory_layout[1].file.segments[1].memory_offset, 0x1970)

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[2].file, None)

  def test_zephyr_10064_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/zephyr-10064.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 3)

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x400000)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x1502c)
    self.assertEqual(len(device_config.memory_layout[0].file.segments), 2)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0xb4)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x131c8)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x131c8)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x13280)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0x1e64)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[1].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[1].file.segments), 1)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].file_offset, 0x13280)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].size, 0x1e64)

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[2].file, None)

  def test_px4_fmu_v5_elf(self): # distance between merged segments > 0x0.
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/px4_fmu-v5_default.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 4) # stm32 has uid registers at 0x1ffff000

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x8_000_000)
    self.assertEqual(len(device_config.memory_layout[0].file.segments), 2)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x1f38b5)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x1f2a1c)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x1f2a1c)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x200000)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0xe99)

    self.assertEqual(len(device_config.memory_layout[2].file.segments), 1)
    self.assertEqual(device_config.memory_layout[2].base_addr, 0x20020000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[2].size, 0x100000)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].file_offset, 0x200000)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].size, 0xe99)

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[3].file, None)

  def test_floormat_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/floormat.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 5) # stm32 has uid registers at 0x1ffff000

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x8020000)
    self.assertEqual(len(device_config.memory_layout[0].file.segments), 3)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0xac4f8)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x100)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x9e5ac) # 0x9e5ac = 0x9e600 - 0x100

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x9e6b0)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x80be5ac - 0x8020000)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0x1110)

    self.assertEqual(device_config.memory_layout[0].file.segments[2].file_offset, 0x9f7c0)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].memory_offset, 0x80bf6bc - 0x8020000)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].size, 0xce3c)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x10000000)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[1].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[1].file.segments), 1)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].file_offset, 0x9f7c0)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].size, 0xce3c)

    # skip the region for stm32 uid registers

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x20_000_000)
    self.assertEqual(device_config.memory_layout[3].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[3].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[3].file.segments), 1)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].file_offset, 0x9e6b0)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].memory_offset, 0x2b0)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].size, 0x1110)

    self.assertEqual(device_config.memory_layout[4].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[4].file, None)

  def test_portenta_stm32h747_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/portenta_STM32H747AII6_CM7.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 6)

    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].base_addr, 0x8000000)

    self.assertEqual(device_config.memory_layout[0].size, 0x427ac)

    self.assertEqual(len(device_config.memory_layout[0].file.segments), 5)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x10000)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x298)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x102a0)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x2a0)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0x3fd66)

    self.assertEqual(device_config.memory_layout[0].file.segments[2].file_offset, 0x50008)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].memory_offset, 0x40008)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].size, 0xa6c)

    self.assertEqual(device_config.memory_layout[0].file.segments[3].file_offset, 0x60000)
    self.assertEqual(device_config.memory_layout[0].file.segments[3].memory_offset, 0x40a74)
    self.assertEqual(device_config.memory_layout[0].file.segments[3].size, 0x438)

    self.assertEqual(device_config.memory_layout[0].file.segments[4].file_offset, 0x60800)
    self.assertEqual(device_config.memory_layout[0].file.segments[4].memory_offset, 0x40eac)
    self.assertEqual(device_config.memory_layout[0].file.segments[4].size, 0x1900)

    # skip the region for stm32 uid registers

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[2].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[2].file.segments), 1)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].file_offset, 0x10000)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].size, 0x298)

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x24000000)
    self.assertEqual(device_config.memory_layout[3].memory_type, MemoryType.RAM)
    self.assertEqual(len(device_config.memory_layout[3].file.segments), 2)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].file_offset, 0x60000)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[3].file.segments[0].size, 0x438)

    self.assertEqual(device_config.memory_layout[3].file.segments[1].file_offset, 0x60800)
    self.assertEqual(device_config.memory_layout[3].file.segments[1].memory_offset, 0x800)
    self.assertEqual(device_config.memory_layout[3].file.segments[1].size, 0x1900)

    self.assertEqual(device_config.memory_layout[4].base_addr, 0x38000000)
    self.assertEqual(device_config.memory_layout[4].size, 0x100000)
    self.assertEqual(device_config.memory_layout[4].memory_type, MemoryType.RAM)
    self.assertEqual(len(device_config.memory_layout[4].file.segments), 0)

    self.assertEqual(device_config.memory_layout[5].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[5].file, None)

  def test_p2im_console_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/p2im.console.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 3)
    self.assertEqual(device_config.memory_layout[0].base_addr, 0x0)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x77fc)

    self.assertEqual(len(device_config.memory_layout[0].file.segments), 4)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x10000)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x400)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x10400)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x400)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0x10)

    self.assertEqual(device_config.memory_layout[0].file.segments[2].file_offset, 0x10410)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].memory_offset, 0x410)
    self.assertEqual(device_config.memory_layout[0].file.segments[2].size, 0x714c)

    self.assertEqual(device_config.memory_layout[0].file.segments[3].file_offset, 0x20200)
    self.assertEqual(device_config.memory_layout[0].file.segments[3].memory_offset, 0x755c)
    self.assertEqual(device_config.memory_layout[0].file.segments[3].size, 0x2a0)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x1fff0000)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[1].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[1].file.segments), 1)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].file_offset, 0x20200)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].memory_offset, 0x200)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].size, 0x2a0)

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.MMIO)
    self.assertEqual(device_config.memory_layout[2].file, None)

  def test_knickerbocker_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/knickerbocker.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 4)

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x800000)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x5fc0)

    self.assertEqual(len(device_config.memory_layout[0].file.segments), 1)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x5fc0)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x01000200)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[1].size, 0x32e89)

    self.assertEqual(len(device_config.memory_layout[1].file.segments), 2)

    self.assertEqual(device_config.memory_layout[1].file.segments[0].file_offset, 0x10200)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[1].file.segments[0].size, 0x214)

    self.assertEqual(device_config.memory_layout[1].file.segments[1].file_offset, 0x10414)
    self.assertEqual(device_config.memory_layout[1].file.segments[1].memory_offset, 0x214)
    self.assertEqual(device_config.memory_layout[1].file.segments[1].size, 0x32c75)

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[2].size, 0x100000)

    self.assertEqual(len(device_config.memory_layout[2].file.segments), 1)

    self.assertEqual(device_config.memory_layout[2].file.segments[0].file_offset, 0x5104c)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].memory_offset, 0x104c)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].size, 0xe659)

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[3].file, None)

  def test_adi_periph_max32655_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/ADI_periph_max32655.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    self.assertEqual(len(device_config.memory_layout), 4)

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x10000000)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x31498)

    self.assertEqual(len(device_config.memory_layout[0].file.segments), 2)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x10000)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x305e8)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x50000)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x305e8)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0xeb0)

    self.assertEqual(device_config.memory_layout[1].base_addr, 0x1007c000)
    self.assertEqual(device_config.memory_layout[1].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[1].size, 0x100000)

    self.assertEqual(len(device_config.memory_layout[1].file.segments), 0)

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[2].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[2].file.segments), 1)

    self.assertEqual(device_config.memory_layout[2].file.segments[0].file_offset, 0x50000)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].size, 0xeb0)

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[3].file, None)

  def test_arducopter_elf(self):
    client = HavocClient(HOST_URL)
    file_metadata = client.upload_file("ci-resources/test-binaries/arducopter.elf")
    device_config, _ = client.infer_config(file_hash=file_metadata.hash)

    for mem in device_config.memory_layout:
      print(hex(mem.base_addr), hex(mem.size), mem.memory_type)

    self.assertEqual(len(device_config.memory_layout), 4)

    self.assertEqual(device_config.memory_layout[0].base_addr, 0x8000000)
    self.assertEqual(device_config.memory_layout[0].memory_type, MemoryType.ROM)
    self.assertEqual(device_config.memory_layout[0].size, 0x19df50)

    self.assertEqual(len(device_config.memory_layout[0].file.segments), 2)

    self.assertEqual(device_config.memory_layout[0].file.segments[0].file_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].memory_offset, 0x0)
    self.assertEqual(device_config.memory_layout[0].file.segments[0].size, 0x19d0a0)

    self.assertEqual(device_config.memory_layout[0].file.segments[1].file_offset, 0x1a2200)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].memory_offset, 0x19d0a0)
    self.assertEqual(device_config.memory_layout[0].file.segments[1].size, 0xeb0)

    # Skip the region for stm32 uid registers

    self.assertEqual(device_config.memory_layout[2].base_addr, 0x20000000)
    self.assertEqual(device_config.memory_layout[2].memory_type, MemoryType.RAM)
    self.assertEqual(device_config.memory_layout[2].size, 0x100000)
    self.assertEqual(len(device_config.memory_layout[2].file.segments), 1)

    self.assertEqual(device_config.memory_layout[2].file.segments[0].file_offset, 0x1a2200)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].memory_offset, 0x2200)
    self.assertEqual(device_config.memory_layout[2].file.segments[0].size, 0x0eb0)

    self.assertEqual(device_config.memory_layout[3].base_addr, 0x40000000)
    self.assertEqual(device_config.memory_layout[3].file, None)

if __name__ == "__main__":
  unittest.main()
