#!/usr/bin/env python3
"""
BIP 375: PSBT Field Type Constants

Minimal BIP 375 field types needed for PSBT v2 validation with silent payments.
"""


class PSBTFieldType:
    """Minimal BIP 375 field types needed for reference validator"""

    # Global fields (required for validation)
    PSBT_GLOBAL_TX_VERSION = 0x02
    PSBT_GLOBAL_INPUT_COUNT = 0x04
    PSBT_GLOBAL_OUTPUT_COUNT = 0x05
    PSBT_GLOBAL_VERSION = 0xFB
    PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
    PSBT_GLOBAL_SP_DLEQ = 0x08

    # Input fields (required for validation)
    PSBT_IN_NON_WITNESS_UTXO = 0x00
    PSBT_IN_WITNESS_UTXO = 0x01
    PSBT_IN_PARTIAL_SIG = 0x02
    PSBT_IN_SIGHASH_TYPE = 0x03
    PSBT_IN_REDEEM_SCRIPT = 0x04
    PSBT_IN_BIP32_DERIVATION = 0x06
    PSBT_IN_PREVIOUS_TXID = 0x0E
    PSBT_IN_OUTPUT_INDEX = 0x0F
    PSBT_IN_TAP_INTERNAL_KEY = 0x17
    PSBT_IN_SP_ECDH_SHARE = 0x1D
    PSBT_IN_SP_DLEQ = 0x1E

    # Output fields (required for validation)
    PSBT_OUT_AMOUNT = 0x03
    PSBT_OUT_SCRIPT = 0x04
    PSBT_OUT_SP_V0_INFO = 0x09
    PSBT_OUT_SP_V0_LABEL = 0x0A
