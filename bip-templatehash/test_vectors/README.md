# `OP_TEMPLATEHASH` test vectors

The test vectors are split into basic sanity checks and more extensive coverage. Both are JSON files containing a JSON
array of JSON objects. Each JSON object in the array represents a Script validation test case.

For [`basics.json`](basics.json), each object contains the following fields:
- `spending_tx`: a hexadecimal string representing a serialized Bitcoin transaction. This is the transaction to be
  validated.
- `input_index`: a JSON integer representing the index of the transaction input for which to perform Script validation.
- `spent_outputs`: a JSON array of hexadecimal strings representing serialized Bitcoin transaction outputs. This is the
  list of outputs pointed to by the inputs of the transaction to be validated.
- `valid`: a JSON boolean. Whether script validation should succeed.
- `comment`: a JSON string. Reason why script validation should succeed or fail.

For [`script_assets_test.json`](script_assets_test.json), each object contains the following fields:
- `tx`: a hexadecimal string representing a serialized Bitcoin transaction. This is the transaction to be validated.
- `index`: a JSON integer representing the index of the transaction input for which to perform Script validation.
- `prevouts`: a JSON array of hexadecimal strings representing serialized Bitcoin transaction outputs. This is the list
  of outputs pointed to by the inputs of the transaction to be validated.
- `flags`: a JSON array of strings representing the script validation flags to enable for this test case.
- `success`: an optional JSON object representing the transaction input fields to set such as script validation
  succeeds. The subfields are the following:
    - `scriptSig`: a JSON hexadecimal string representing the serialized input script.
    - `witness`: a JSON array of hexadecimal strings representing the witness stack for this input.
- `final`: an optional JSON boolean which, if true, indicates script validation should always succeed with more
  validation flags than specified in `flags`.
- `failure`: an optional JSON object representing the transaction input fields to set such as script validation
  fails. The subfields are the following:
    - `scriptSig`: a JSON hexadecimal string representing the serialized input script.
    - `witness`: a JSON array of hexadecimal strings representing the witness stack for this input.

An example usage of [`basics.json`](basics.json) can be found [here](TODO: link to PR). An example usage of
[`script_assets_test.json`](script_assets_test.json) can be found [here](https://github.com/bitcoin/bitcoin/blob/f490f5562d4b20857ef8d042c050763795fd43da/src/test/script_tests.cpp#L1558).
