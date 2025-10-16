import struct
import io
from typing import Dict

class TestcaseInput:
    # A channel is a (fuzzed) memory location with a corresponding byte array.
    channels: Dict[int, bytes]

    def __init__(self, channels: Dict[int, bytes]) -> None:
      self.channels = channels

    def __repr__(self) -> str:
      header = "\n Address   " + "| Data\n"
      header += "-----------|" + ("-" * 20) + "\n"
      content = "\n".join([f"{hex(addr)} | {' '.join([f'{b:02x}' for b in data])}" for addr, data in self.channels.items()])
      return header + content

    @staticmethod
    def from_bytes(bytes: bytes) -> 'TestcaseInput':
        reader = io.BytesIO(bytes)
        magic = reader.read(4)
        if magic != b'hav\x02':
          raise ValueError("Invalid version: " + str(magic))

        try:
          num_channels = struct.unpack('<I', reader.read(4))[0]
          if num_channels > 0x10000:
            raise ValueError("Too many channels")
        except struct.error:
          raise ValueError("Invalid input: failed to read number of channels")

        channel_headers = []
        for i in range(num_channels):
          try:
            channel_addr = struct.unpack('<Q', reader.read(8))[0]
            channel_len = struct.unpack('<Q', reader.read(8))[0]
            channel_headers.append((channel_addr, channel_len))
          except struct.error:
            raise ValueError("Invalid input: failed to read channel header")

        channels = {}
        for channel_addr, channel_len in channel_headers:
          if channel_len > 0x100000:
            raise ValueError("Channel too long")
          channels[channel_addr] = reader.read(channel_len)

        return TestcaseInput(channels)