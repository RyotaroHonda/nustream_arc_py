import socket
from typing import List


class NuStream:
    MAGIC = 0x5A
    HEADER_SIZE = 12
    MAX_PAYLOAD_BYTES = 1024

    CMD_READ = 0x1
    CMD_WRITE = 0x2
    CMD_INT_READ = 0x3
    CMD_INT_WRITE = 0x4

    MODE_LIST = 0x01
    MODE_AUTOINCREMENT = 0x02

    FLAG_ACK = 0x01
    FLAG_UDP_ERROR = 0x02
    FLAG_BUS_ERROR = 0x04

    def __init__(self, timeout_sec: float = 1.0):
        self.tx_header: List[int] = []
        self.tx_payload: List[int] = []
        self.rx_header: List[int] = []
        self.rx_payload: List[int] = []
        self.ack_received: bool = False
        self.timeout_sec = timeout_sec

    @staticmethod
    def _u32_to_bytes_be(value: int) -> bytes:
        return int(value & 0xFFFFFFFF).to_bytes(4, byteorder="big")

    @staticmethod
    def _bytes_to_u32_be(data: bytes) -> int:
        if len(data) != 4:
            raise ValueError("Input length must be 4 bytes.")
        return int.from_bytes(data, byteorder="big")

    def _payload_list_to_bytes(self, payload: List[int]) -> bytes:
        return b"".join(self._u32_to_bytes_be(v) for v in payload)

    def _bytes_to_payload_list(self, payload_bytes: bytes) -> List[int]:
        if len(payload_bytes) % 4 != 0:
            raise ValueError("Payload length must be a multiple of 4 bytes.")
        return [
            self._bytes_to_u32_be(payload_bytes[i : i + 4])
            for i in range(0, len(payload_bytes), 4)
        ]

    def _header_list_to_bytes(self, header: List[int]) -> bytes:
        if len(header) != self.HEADER_SIZE:
            raise ValueError("Header must be exactly 12 bytes.")
        return bytes(header)

    def _bytes_to_header_list(self, header_bytes: bytes) -> List[int]:
        if len(header_bytes) != self.HEADER_SIZE:
            raise ValueError("Header must be exactly 12 bytes.")
        return list(header_bytes)

    def _parse_header_fields(self, header_list: List[int]) -> dict:
        if len(header_list) != self.HEADER_SIZE:
            raise ValueError("Header list must have 12 bytes.")

        b = bytes(header_list)
        return {
            "magic": b[0],
            "version": (b[1] >> 4) & 0x0F,
            "cmd": b[1] & 0x0F,
            "mode": b[2],
            "flags": b[3],
            "length": (b[4] << 8) | b[5],
            "reserved": (b[6] << 8) | b[7],
            "address": int.from_bytes(b[8:12], byteorder="big"),
        }

    def _validate_tx_consistency(self) -> None:
        """
        Validate consistency between the transmit header and transmit payload.

        Checks based on the protocol specification:
        - Write commands: Length must match the actual payload size in bytes
        - List-mode read commands: Length must match the actual payload size in bytes
        - Sequential read commands: payload must be empty, and Length may differ
          from the payload size because it represents the requested read size
        """
        if len(self.tx_header) != self.HEADER_SIZE:
            raise ValueError("Transmit header is not set. Call MakeHeader() first.")

        info = self._parse_header_fields(self.tx_header)

        cmd = info["cmd"]
        mode = info["mode"]
        length = info["length"]

        payload_bytes = len(self.tx_payload) * 4
        is_list_mode = bool(mode & self.MODE_LIST)
        is_read = cmd in (self.CMD_READ, self.CMD_INT_READ)
        is_write = cmd in (self.CMD_WRITE, self.CMD_INT_WRITE)

        if payload_bytes > self.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload too large: {payload_bytes} bytes "
                f"(max {self.MAX_PAYLOAD_BYTES} bytes)"
            )

        if is_write:
            if length != payload_bytes:
                raise ValueError(
                    "Header Length does not match transmit payload size "
                    f"for write command: Length={length}, payload_bytes={payload_bytes}"
                )
            return

        if is_read:
            if is_list_mode:
                if length != payload_bytes:
                    raise ValueError(
                        "Header Length does not match transmit payload size "
                        f"for list-mode read: Length={length}, payload_bytes={payload_bytes}"
                    )
            else:
                if payload_bytes != 0:
                    raise ValueError(
                        "Sequential read must send empty payload, "
                        f"but payload_bytes={payload_bytes}"
                    )
                if length > self.MAX_PAYLOAD_BYTES:
                    raise ValueError(
                        f"Requested read Length too large: {length} bytes "
                        f"(max {self.MAX_PAYLOAD_BYTES} bytes)"
                    )
            return

        raise ValueError(f"Unsupported command value: {cmd}")

    def PrintHeader(self, header_list: List[int]) -> None:
        info = self._parse_header_fields(header_list)

        print("========== NuStream Header ==========")
        print(f"Magic    : 0x{info['magic']:02X}")
        print(f"Version  : 0x{info['version']:01X} ({info['version']})")
        print(f"Cmd      : 0x{info['cmd']:01X} ({info['cmd']})")
        print(f"Mode     : 0x{info['mode']:02X} ({info['mode']:08b})")
        print(f"Flags    : 0x{info['flags']:02X} ({info['flags']:08b})")
        print(f"  Ack       : {1 if (info['flags'] & self.FLAG_ACK) else 0}")
        print(f"  UdpError  : {1 if (info['flags'] & self.FLAG_UDP_ERROR) else 0}")
        print(f"  BusError  : {1 if (info['flags'] & self.FLAG_BUS_ERROR) else 0}")
        print(f"Length   : 0x{info['length']:04X} ({info['length']} bytes)")
        print(f"Reserved : 0x{info['reserved']:04X}")
        print(f"Address  : 0x{info['address']:08X}")
        print("==================================")

    def DumpPayload(self, payload_list: List[int]) -> None:
        print("========== NuStream Payload Dump ==========")
        if not payload_list:
            print("(empty)")
        else:
            for i, value in enumerate(payload_list):
                print(f"[{i:04d}] 0x{value & 0xFFFFFFFF:08X}")
        print("=========================================")

    def SetPayload(self, payload_list: List[int]) -> None:
        payload_bytes = len(payload_list) * 4
        if payload_bytes > self.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload too large: {payload_bytes} bytes "
                f"(max {self.MAX_PAYLOAD_BYTES} bytes)"
            )

        self.tx_payload = [int(v) & 0xFFFFFFFF for v in payload_list]

    def GetPayload(self) -> List[int]:
        return self.rx_payload.copy()

    def MakeHeader(
        self, Version: int, Cmd: int, Mode: int, Length: int, Address: int
    ) -> None:
        if not (0 <= Version <= 0x0F):
            raise ValueError("Version must be 4-bit value.")
        if not (0 <= Cmd <= 0x0F):
            raise ValueError("Cmd must be 4-bit value.")
        if not (0 <= Mode <= 0xFF):
            raise ValueError("Mode must be 8-bit value.")
        if not (0 <= Length <= 0xFFFF):
            raise ValueError("Length must be 16-bit value.")
        if Length > self.MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Length too large: {Length} bytes "
                f"(max {self.MAX_PAYLOAD_BYTES} bytes)"
            )
        if not (0 <= Address <= 0xFFFFFFFF):
            raise ValueError("Address must be 32-bit value.")

        header_bytes = bytearray(self.HEADER_SIZE)
        header_bytes[0] = self.MAGIC
        header_bytes[1] = ((Version & 0x0F) << 4) | (Cmd & 0x0F)
        header_bytes[2] = Mode & 0xFF
        header_bytes[3] = 0x00
        header_bytes[4] = (Length >> 8) & 0xFF
        header_bytes[5] = Length & 0xFF
        header_bytes[6] = 0x00
        header_bytes[7] = 0x00
        header_bytes[8:12] = Address.to_bytes(4, byteorder="big")

        self.tx_header = list(header_bytes)

    def ExecComm(self, ip_addr: str, port: int) -> None:
        self._validate_tx_consistency()

        tx_data = self._header_list_to_bytes(
            self.tx_header
        ) + self._payload_list_to_bytes(self.tx_payload)

        self.ack_received = False
        self.rx_header = []
        self.rx_payload = []

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout_sec)

        try:
            sock.sendto(tx_data, (ip_addr, port))

            rx_data, _ = sock.recvfrom(4096)

            if len(rx_data) < self.HEADER_SIZE:
                print("Received packet is too short to contain a valid header.")
                self.ack_received = False
                return

            rx_header_bytes = rx_data[: self.HEADER_SIZE]
            rx_payload_bytes = rx_data[self.HEADER_SIZE :]

            self.rx_header = self._bytes_to_header_list(rx_header_bytes)

            try:
                self.rx_payload = self._bytes_to_payload_list(rx_payload_bytes)
            except ValueError:
                print("Received payload length is invalid.")
                self.rx_payload = []
                self.ack_received = False
                return

            magic = rx_header_bytes[0]
            flags = rx_header_bytes[3]

            if magic == self.MAGIC and (flags & self.FLAG_ACK):
                self.ack_received = True
            else:
                self.ack_received = False

        except socket.timeout:
            print("Timeout, no ACK reply.")
            self.ack_received = False

        finally:
            sock.close()
