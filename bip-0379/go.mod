module bip-379

go 1.25.0

// That commit only exists in the pull request it belongs to
// (btcsuite/btcd#2568), and the module proxy cannot resolve a commit that is
// not on a branch or tag of the repository, so the very same commit is taken
// from the fork it was pushed from. Once it is merged, this line can go.
replace github.com/btcsuite/btcd/descriptors => github.com/guggero/btcd/descriptors v0.0.0-20260822123210-2f50ef071048

require (
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	// The descriptors module isn't in master yet, see replace directive above.
	github.com/btcsuite/btcd/descriptors v0.0.0-00000000000000-000000000000
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.0
)

require (
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
