# BIP327 test vectors

BIP327 specifies the length and number of the inputs of each algorithm, for example that each tweak is a 32-byte array and that there is one tweak mode for each tweak.
The test vectors only contain inputs that meet these specifications.
Since BIP327 does not specify how algorithms handle other inputs, such as a 31-byte tweak or a missing tweak mode, the test vectors do not test them.

A test vector should only be added if it detects a plausible implementation mistake that the other test vectors do not detect.
The comment of the test vector names the mistake, for example "Detects implementations that set gacc to g instead of multiplying it by g".
