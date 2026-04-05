import argparse

from nustream import nustream as ns


def parse_args():
    parser = argparse.ArgumentParser(
        description="Write 4 bytes via NuStream in sequential mode."
    )

    parser.add_argument("ip_address", help="Destination IP address")

    parser.add_argument(
        "nustream_address",
        help="NuStream address in hexadecimal format (example: 0xF0000005)",
    )

    parser.add_argument(
        "payload_data", help="Payload data in hexadecimal format (example: 0x12345678)"
    )

    parser.add_argument(
        "--int-write",
        action="store_true",
        help="Use CMD_INT_WRITE instead of CMD_WRITE",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=5004,
        help="Destination UDP port number (default: 5004)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds (default: 1.0)",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    try:
        address = int(args.nustream_address, 16)
    except ValueError:
        raise ValueError(
            "nustream_address must be a hexadecimal value such as 0xF0000005"
        )

    try:
        payload_data = int(args.payload_data, 16)
    except ValueError:
        raise ValueError("payload_data must be a hexadecimal value such as 0x12345678")

    if not (0 <= payload_data <= 0xFFFFFFFF):
        raise ValueError("payload_data must fit in 32 bits.")

    cmd = ns.NuStream.CMD_INT_WRITE if args.int_write else ns.NuStream.CMD_WRITE

    nsu = ns.NuStream(timeout_sec=args.timeout)

    # Sequential write request with one 32-bit data word
    nsu.SetPayload([payload_data])

    nsu.MakeHeader(
        Version=1,
        Cmd=cmd,
        Mode=ns.NuStream.MODE_AUTOINCREMENT,
        Length=4,
        Address=address,
    )

    nsu.ExecComm(args.ip_address, args.port)

    print("ACK received:", nsu.ack_received)
    nsu.PrintHeader(nsu.rx_header)
    rx_data = nsu.GetPayload()
    nsu.DumpPayload(rx_data)


if __name__ == "__main__":
    main()
