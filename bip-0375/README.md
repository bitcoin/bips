# BIP-375 Validation Reference

A reference validation implementation for BIP-375: Sending Silent Payments with PSBTs.

## Core Files
- **`validator/bip352_crypto.py`** - Silent payment output script derivation
- **`validator/inputs.py`** - PSBT input utility functions
- **`validator/psbt_bip375.py`** - BIP-375 specific PSBT/PSBTMap extensions
- **`validator/validate_psbt.py`** - Main BIP-375 validation functions
- **`test_runner.py`** - Test infrastructure (executable)

## Dependencies
- **`deps/bitcoin_test/psbt.py`** - Bitcoin test framework PSBT module - [PR #21283](https://github.com/bitcoin/bitcoin/pull/21283)
- **`deps/bitcoin_test/messages.py`** - Bitcoin test framework primitives and message structures
- **`deps/dleq.py`** - Reference DLEQ implementation from BIP-374
- **`deps/secp256k1lab/`** - vendored copy of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb) library at version 1.0.0

## Testing

### Run Tests

```bash
python test_runner.py                    # Run all tests
python test_runner.py -v                 # Verbose mode with detailed validation status
python test_runner.py -vv                # More verbose with validation check failure reason

python test_runner.py -f vectors.json    # Use custom test vector file
```

### Generating Test Vectors

Test vectors were generated using [test_generator.py](https://github.com/macgyver13/bip375-test-generator/)
