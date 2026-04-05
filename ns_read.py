import argparse

from nustream import nustream as ns


def parse_args():
    parser = argparse.ArgumentParser(description="Read 4 bytes via NuStream.")

    parser.add_argument("ip_address", help="Destination IP address")

    parser.add_argument(
        "nustream_address",
        help="NuStream address in hexadecimal format (example: 0xF0000005)",
    )

    parser.add_argument(
        "--int-read", action="store_true", help="Use CMD_INT_READ instead of CMD_READ"
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

    cmd = ns.NuStream.CMD_INT_READ if args.int_read else ns.NuStream.CMD_READ

    nsu = ns.NuStream(timeout_sec=args.timeout)

    # Since this is a sequential read request, the payload must be empty
    nsu.SetPayload([])

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
