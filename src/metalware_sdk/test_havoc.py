from metalware_sdk.havoc_client import HavocClient
from metalware_sdk.havoc_common_schema import *
from unittest import TestCase, main

def pretty_memory_config(memory_config: MemoryConfig) -> str:
  result = ""
  for memory in memory_config.memory_layout:
    result += f"{hex(memory.base_addr)} {hex(memory.size)} {memory.memory_type} {memory.file}\n"
  return result

def get_rom_addr(memory_config: MemoryConfig) -> int:
  for memory in memory_config.memory_layout:
      if memory.memory_type == MemoryType.ROM:
          return memory.base_addr
  raise Exception("ROM address not found")

class TestHavoc(TestCase):
    def test_alias_elf(self):
        client = HavocClient("http://localhost:8080")
        file_metadata = client.upload_file("test_binaries/alias-test.elf")

        memory_config = client.infer_memory_config(file_hash=file_metadata.hash)

        memory_config.memory_layout.append(Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM, aliased_to=0x24000000))
        memory_config.memory_layout.append(Memory(base_addr=0x24000000, size=0x100000, memory_type=MemoryType.RAM))

        project_config = ProjectConfig(memory_config)
        client.create_project("alias-test.tmp", project_config, overwrite=True)

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash))
        client.create_image(project_name="alias-test.tmp", image_name="default", image_config=image_config)

        client.start_run(project_name="alias-test.tmp", config=RunConfig(image_name="default", dry_run=True))

    def test_zephyr_rom_infer(self):
        client = HavocClient("http://localhost:8080")
        file_metadata = client.upload_file("test_binaries/zephyr-10064.bin")

        memory_config = client.infer_memory_config(file_hash=file_metadata.hash)
        rom_addr = get_rom_addr(memory_config)

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        raw_image = RawImage(segments=[RawImageSegment(address=rom_addr, hash=file_metadata.hash)])
        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

    def test_zephyr_rom_no_infer(self):
        client = HavocClient("http://localhost:8080")

        memory_config = MemoryConfig(memory_layout=[
           Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
           Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
           Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
        ], entry_address=0x400000)

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        # Upload ROM
        upload_metadata = client.upload_file("test_binaries/zephyr-10064.bin")

        # Create ImageConfig
        raw_image = RawImage(segments=[RawImageSegment(address=0x400000, hash=upload_metadata.hash)])

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        # Create Run
        client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

    def test_zephyr_elf(self):
        client = HavocClient("http://localhost:8080")
        file_metadata = client.upload_file("test_binaries/zephyr-10064.elf")

        memory_config = client.infer_memory_config(file_hash=file_metadata.hash)
        memory_config.entry_address = 0x400000

        print(pretty_memory_config(memory_config))

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=file_metadata.hash))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))

    def test_overlapping_regions(self):
        client = HavocClient("http://localhost:8080")

        memory_config = MemoryConfig(memory_layout=[
            Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
            Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
            Memory(base_addr=0x20000500, size=0x100000, memory_type=MemoryType.RAM),
            Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO)
        ], entry_address=0x400000)

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        upload_metadata = client.upload_file("test_binaries/zephyr-10064.elf")

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=upload_metadata.hash))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        with self.assertRaises(Exception) as context:
            client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
            self.assertTrue("overlaps" in str(context.exception))

    def test_missing_regions(self):
        client = HavocClient("http://localhost:8080")

        memory_config = MemoryConfig(memory_layout=[
            Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM),
            Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
            Memory(base_addr=0x22000000, size=0x100000, memory_type=MemoryType.RAM),
        ], entry_address=0x400000)

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        upload_metadata = client.upload_file("test_binaries/zephyr-10064.elf")

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(elf=upload_metadata.hash))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        # Assert exception is thrown
        with self.assertRaises(Exception) as context:
            client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
            self.assertTrue("missing" in str(context.exception))

    def test_undersized_rom(self):
        client = HavocClient("http://localhost:8080")

        memory_config = MemoryConfig(memory_layout=[
           Memory(base_addr=0x400000, size=0x10, memory_type=MemoryType.ROM),
           Memory(base_addr=0x20000000, size=0x100000, memory_type=MemoryType.RAM),
           Memory(base_addr=0x40000000, size=0x100000, memory_type=MemoryType.MMIO),
        ], entry_address=0x400000)

        project_config = ProjectConfig(memory_config)
        client.create_project("zephyr-10064.tmp", project_config, overwrite=True)

        upload_metadata = client.upload_file("test_binaries/zephyr-10064.bin")

        raw_image = RawImage(segments=[RawImageSegment(address=0x400000, hash=upload_metadata.hash)])

        image_config = ImageConfig(image_arch=ImageArch.CORTEX_M, image_format=ImageFormat(raw=raw_image))
        client.create_image(project_name="zephyr-10064.tmp", image_name="default", image_config=image_config)

        with self.assertRaises(Exception) as context:
            client.start_run(project_name="zephyr-10064.tmp", config=RunConfig(image_name="default", dry_run=True))
            self.assertTrue("too small" in str(context.exception))

    def test_create_rename_delete_project(self):
        client = HavocClient("http://localhost:8080")
        # Create project
        client.create_project("dummy.tmp", ProjectConfig(MemoryConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)], entry_address=0x400000)), overwrite=True)

        # Rename project
        client.rename_project(project_name="dummy.tmp", new_name="dummy")

        # Check that project was renamed
        project_config = client.get_project_config("dummy")
        self.assertEqual(len(project_config.memory_config.memory_layout), 1)
        self.assertEqual(project_config.memory_config.memory_layout[0].base_addr, 0x400000)
        self.assertEqual(project_config.memory_config.memory_layout[0].size, 0x100000)
        self.assertEqual(project_config.memory_config.memory_layout[0].memory_type, MemoryType.ROM)

        # Delete project
        client.delete_project("dummy")

        # Check that project was deleted
        with self.assertRaises(Exception) as context:
            client.get_project_config("dummy")

    def test_set_project_config(self):
        try: client.delete_project("dummy-2")
        except Exception as e: pass

        client = HavocClient("http://localhost:8080")
        client.create_project("dummy-2", ProjectConfig(MemoryConfig(memory_layout=[Memory(base_addr=0x500000, size=0x100000, memory_type=MemoryType.ROM)], entry_address=0x500000)))

        # Check that project config was set
        project_config = client.get_project_config("dummy-2")
        self.assertEqual(len(project_config.memory_config.memory_layout), 1)
        self.assertEqual(project_config.memory_config.memory_layout[0].base_addr, 0x500000)
        self.assertEqual(project_config.memory_config.memory_layout[0].size, 0x100000)
        self.assertEqual(project_config.memory_config.memory_layout[0].memory_type, MemoryType.ROM)
        self.assertEqual(project_config.memory_config.entry_address, 0x500000)

        # Set project config
        client.set_project_config("dummy-2", ProjectConfig(MemoryConfig(memory_layout=[Memory(base_addr=0x400000, size=0x100000, memory_type=MemoryType.ROM)], entry_address=0x400000)))

        # Check that project config was set
        project_config = client.get_project_config("dummy-2")
        self.assertEqual(len(project_config.memory_config.memory_layout), 1)
        self.assertEqual(project_config.memory_config.memory_layout[0].base_addr, 0x400000)
        self.assertEqual(project_config.memory_config.memory_layout[0].size, 0x100000)
        self.assertEqual(project_config.memory_config.memory_layout[0].memory_type, MemoryType.ROM)
        self.assertEqual(project_config.memory_config.entry_address, 0x400000)

        # Delete project
        client.delete_project("dummy-2")

        # Check that project was deleted
        with self.assertRaises(Exception) as context:
            client.get_project_config("dummy-2")

    # TODO: test portenta, dryer, mcf pulse, adi ble, fellow, p2im.console, arducopter
    # TODO: test image config update
    # TODO: test multi-segment RAW image
    # TODO: test set image symbols
    # TODO: test get image symbols

if __name__ == "__main__":
    main()