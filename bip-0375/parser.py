#!/usr/bin/env python3
"""
BIP 375: PSBT Structure Parser

Functions for parsing PSBT v2 structure into global, input, and output field maps.
"""

import struct
from typing import Dict, List, Tuple

from constants import PSBTFieldType


def parse_psbt_structure(
    psbt_data: bytes,
) -> Tuple[Dict[int, bytes], List[Dict[int, bytes]], List[Dict[int, bytes]]]:
    """Parse PSBT structure into global, input, and output field maps"""

    def parse_compact_size_uint(data: bytes, offset: int) -> Tuple[int, int]:
        """Parse compact size uint and return (value, new_offset)"""
        if offset >= len(data):
            raise ValueError("Not enough data")

        first_byte = data[offset]
        if first_byte < 0xFD:
            return first_byte, offset + 1
        elif first_byte == 0xFD:
            return struct.unpack("<H", data[offset + 1 : offset + 3])[0], offset + 3
        elif first_byte == 0xFE:
            return struct.unpack("<L", data[offset + 1 : offset + 5])[0], offset + 5
        else:
            return struct.unpack("<Q", data[offset + 1 : offset + 9])[0], offset + 9

    def parse_section(data: bytes, offset: int) -> Tuple[Dict[int, bytes], int]:
        """Parse a PSBT section and return (field_map, new_offset)"""
        fields = {}

        while offset < len(data):
            # Read key length
            key_len, offset = parse_compact_size_uint(data, offset)
            if key_len == 0:  # End of section
                break

            # Read key data
            if offset + key_len > len(data):
                raise ValueError("Truncated key data")
            key_data = data[offset : offset + key_len]
            offset += key_len

            # Read value length
            value_len, offset = parse_compact_size_uint(data, offset)

            # Read value data
            if offset + value_len > len(data):
                raise ValueError("Truncated value data")
            value_data = data[offset : offset + value_len]
            offset += value_len

            # Extract field type and handle key-value pairs
            if key_data:
                field_type = key_data[0]
                key_content = key_data[1:] if len(key_data) > 1 else b""

                # For BIP 375 and BIP-174 key-value fields, store both key and value
                if field_type in [
                    PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_GLOBAL_SP_DLEQ,
                    PSBTFieldType.PSBT_IN_SP_ECDH_SHARE,
                    PSBTFieldType.PSBT_IN_SP_DLEQ,
                    PSBTFieldType.PSBT_IN_BIP32_DERIVATION,
                    PSBTFieldType.PSBT_IN_PARTIAL_SIG,
                ]:
                    fields[field_type] = {"key": key_content, "value": value_data}
                else:
                    # For standard PSBT fields, just store value
                    fields[field_type] = value_data

        return fields, offset

    if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
        raise ValueError("Invalid PSBT magic")

    offset = 5

    # Parse global section
    global_fields, offset = parse_section(psbt_data, offset)

    # Determine number of inputs and outputs (standard PSBT fields)
    num_inputs = (
        global_fields.get(PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT, b"\x00")[0]
        if PSBTFieldType.PSBT_GLOBAL_INPUT_COUNT in global_fields
        else 1
    )
    num_outputs = (
        global_fields.get(PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT, b"\x00")[0]
        if PSBTFieldType.PSBT_GLOBAL_OUTPUT_COUNT in global_fields
        else 1
    )

    # Parse input sections
    input_maps = []
    for _ in range(num_inputs):
        input_fields, offset = parse_section(psbt_data, offset)
        input_maps.append(input_fields)

    # Parse output sections
    output_maps = []
    for _ in range(num_outputs):
        output_fields, offset = parse_section(psbt_data, offset)
        output_maps.append(output_fields)

    return global_fields, input_maps, output_maps
