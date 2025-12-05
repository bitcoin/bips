# BIP 375 Reference Implementation

This directory contains reference implementation for BIP 375: Sending Silent Payments with PSBTs.

## Core Files
- **`constants.py`** - PSBT field type definitions
- **`parser.py`** - PSBT structure parsing
- **`inputs.py`** - Input validation helpers
- **`dleq.py`** - DLEQ proof validation
- **`validator.py`** - Main BIP 375 validator
- **`test_runner.py`** - Test infrastructure (executable)

## Dependencies
- **`../bip-0374/reference.py`** - BIP 374 DLEQ proof reference
- **`../bip-0374/secp256k1.py`** - secp256k1 implementation

## Testing

### Test Vectors
- **`test_vectors.json`** - 17 test vectors (13 invalid + 4 valid) covering:
  - Invalid input types (P2MS, non-standard scripts)
  - Missing/invalid DLEQ proofs
  - ECDH share validation
  - Output script verification
  - SIGHASH requirements
  - BIP-352 output address matching

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-examples/blob/main/python/tests/test_generator.py)

### Run Tests

```bash
python test_runner.py                    # Run all tests
python test_runner.py -v                 # Verbose mode with detailed errors
```

**Expected output:** All 17 tests should pass validation (4 valid accepted, 13 invalid rejected).

## Validation Layers

The validator implements progressive validation:
1. **PSBT Structure** - Parse PSBT v2 format
2. **Input Eligibility** - Validate eligible input types (P2PKH, P2WPKH, P2TR, P2SH-P2WPKH)
3. **DLEQ Proofs** - Verify ECDH share correctness using BIP-374
4. **Output Fields** - Check PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO requirements
5. **BIP-352 Outputs** - Validate output scripts match expected silent payment addresses

## Examples

Demo implementations using this reference can be found in [bip375-examples](https://github.com/macgyver13/bip375-examples/)
