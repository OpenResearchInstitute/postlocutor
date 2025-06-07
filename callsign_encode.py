#!/usr/bin/env python3


def encode_callsign(callsign: str) -> int:
    """
    Encodes a callsign into a 6-byte binary format.

    The callsign is any combination of uppercase letters, digits,
    hyphens, slashes, and periods. Each character is encoded base-40.

    :param callsign: The callsign to encode.
    :return: A 6-byte binary representation of the callsign.
    """
    encoded = 0

    for c in callsign[::-1]:
        encoded *= 40
        if "A" <= c <= "Z":
            encoded += ord(c) - ord("A") + 1
        elif "0" <= c <= "9":
            encoded += ord(c) - ord("0") + 27
        elif c == "-":
            encoded += 37
        elif c == "/":
            encoded += 38
        elif c == ".":
            encoded += 39
        else:
            raise ValueError(f"Invalid character '{c}' in callsign.")

    if encoded > 0xFFFFFFFFFFFF:
        raise ValueError("Encoded callsign exceeds maximum length of 6 bytes.")

    return encoded


def decode_callsign(encoded: int) -> str:
    callsign_map = {
        1: "A",
        2: "B",
        3: "C",
        4: "D",
        5: "E",
        6: "F",
        7: "G",
        8: "H",
        9: "I",
        10: "J",
        11: "K",
        12: "L",
        13: "M",
        14: "N",
        15: "O",
        16: "P",
        17: "Q",
        18: "R",
        19: "S",
        20: "T",
        21: "U",
        22: "V",
        23: "W",
        24: "X",
        25: "Y",
        26: "Z",
        27: "0",
        28: "1",
        29: "2",
        30: "3",
        31: "4",
        32: "5",
        33: "6",
        34: "7",
        35: "8",
        36: "9",
        37: "-",
        38: "/",
        39: ".",
    }

    decoded: str = ""
    while encoded > 0:
        remainder = encoded % 40
        if remainder in callsign_map:
            decoded = callsign_map[remainder] + decoded
        else:
            raise ValueError(f"Invalid encoded value: {remainder}")
        encoded //= 40
    return decoded[::-1]  # Reverse to get the correct order


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python callsign_encode.py <callsign>")
        sys.exit(1)

    callsign = sys.argv[1]
    try:
        encoded_callsign = encode_callsign(callsign)
        print(f"Encoded callsign: 0x{encoded_callsign:012x}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        decoded_callsign = decode_callsign(encoded_callsign)
        print(f"Decoded callsign: {decoded_callsign}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
