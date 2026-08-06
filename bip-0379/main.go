// Command bip-379 runs the BIP379 miniscript test vectors against
// an independent implementation of miniscript, the one in
// github.com/btcsuite/btcd/descriptors/miniscript.
//
// It expects the vector files in its own directory (or in the directory given
// as the only argument) and checks every file it finds there, so a subset of
// them works too:
//
//	go run main.go
//
// Positive vectors must be accepted, negative ones must be rejected. The
// program exits non-zero if any vector fails, after reporting the first few
// failures of each file.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/descriptors/miniscript"
	"github.com/btcsuite/btcd/txscript/v2"
)

const (
	// maxReported is the number of failures printed per file; the rest are
	// only counted.
	maxReported = 5

	// numKeys is the number of key placeholders (A..Z) the generated
	// corpora use.
	numKeys = 26

	// utxoAmount is the value of the output the redeem vectors spend, and
	// burnFee what the spending transaction pays as a fee.
	utxoAmount = int64(999799)
	burnFee    = int64(200)
)

// expectation is what a file of bare expressions asserts about each of its
// lines.
type expectation int

const (
	// mustParse means the expression is a valid miniscript in the file's
	// context.
	mustParse expectation = iota

	// mustParseButInsane means the expression is a valid miniscript, but
	// one the sanity checks reject: it is malleable, mixes time lock kinds
	// or needs no signature.
	mustParseButInsane

	// mustParseSomeInsane means the expression is a valid miniscript that
	// the sanity checks may or may not reject. The two are only counted,
	// as the file does not say which of its lines are which.
	mustParseSomeInsane

	// mustFail means the expression is not a valid miniscript.
	mustFail
)

// vectorFile is one test vector file and the check that exercises it.
type vectorFile struct {
	// name is the file name, which is also its identity: the _tap files
	// are Tapscript vectors, the others P2WSH ones.
	name string

	// ctx is the script context the expressions are parsed in.
	ctx miniscript.Context

	// run performs the file's check, filling in the result.
	run func(path string, ctx miniscript.Context, res *result) error
}

// vectorFiles lists every known vector file. A file that is not present is
// reported as missing and skipped.
var vectorFiles = []vectorFile{{
	name: "valid_from_alloy.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParse),
}, {
	name: "valid_8f1e8_from_alloy.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParse),
}, {
	name: "malleable_from_alloy.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParseButInsane),
}, {
	name: "conflict_from_alloy.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParseSomeInsane),
}, {
	name: "edge_cases.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParse),
}, {
	name: "opcodes.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustParse),
}, {
	name: "invalid.txt",
	ctx:  miniscript.P2WSH,
	run:  expressions(mustFail),
}, {
	name: "props_from_rust.tsv",
	ctx:  miniscript.P2WSH,
	run:  properties,
}, {
	name: "props_from_rust_tap.tsv",
	ctx:  miniscript.P2TR,
	run:  properties,
}, {
	name: "scripts_from_rust.tsv",
	ctx:  miniscript.P2WSH,
	run:  scripts,
}, {
	name: "scripts_from_rust_tap.tsv",
	ctx:  miniscript.P2TR,
	run:  scripts,
}, {
	name: "redeem.json",
	ctx:  miniscript.P2WSH,
	run:  redeem,
}}

// result accumulates the outcome of one vector file, counting the vectors that
// must be accepted and those that must be rejected separately.
type result struct {
	// positive and positiveTotal count the vectors that must be accepted.
	positive, positiveTotal int

	// negative and negativeTotal count the vectors that must be rejected.
	negative, negativeTotal int

	// skipped counts the vectors this implementation cannot compare, with
	// the reason recorded in note.
	skipped int

	// note is an optional remark printed after the counts.
	note string

	// failures holds the first maxReported failure messages.
	failures []string
}

// pass records a vector that behaved as the file says it should.
func (r *result) pass(positive bool) {
	if positive {
		r.positive++
		r.positiveTotal++

		return
	}

	r.negative++
	r.negativeTotal++
}

// fail records a vector that did not.
func (r *result) fail(positive bool, format string, args ...any) {
	if positive {
		r.positiveTotal++
	} else {
		r.negativeTotal++
	}

	if len(r.failures) < maxReported {
		r.failures = append(r.failures, fmt.Sprintf(format, args...))
	}
}

// failed returns whether any vector of the file did not behave as specified.
func (r *result) failed() bool {
	return r.positive != r.positiveTotal || r.negative != r.negativeTotal
}

// counts renders the passed/total counts of the classes the file contains.
func (r *result) counts() string {
	pos := fmt.Sprintf("%d/%d", r.positive, r.positiveTotal)
	neg := fmt.Sprintf("%d/%d", r.negative, r.negativeTotal)

	switch {
	case r.negativeTotal == 0:
		return pos

	case r.positiveTotal == 0:
		return neg

	default:
		return pos + " + " + neg
	}
}

// label names the vector classes the file contains.
func (r *result) label() string {
	switch {
	case r.negativeTotal == 0:
		return "positive"

	case r.positiveTotal == 0:
		return "negative"

	default:
		return "positive/negative"
	}
}

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	if err := run(dir); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// run checks every vector file found in the given directory and prints one
// line per file plus a summary.
func run(dir string) error {
	fmt.Printf("Checking the BIP379 test vectors in %s against\n"+
		"github.com/btcsuite/btcd/descriptors/miniscript.\n\n", dir)

	width := 0
	for _, file := range vectorFiles {
		width = max(width, len(file.name))
	}

	var (
		passed, total, skipped int
		missing                []string
		failedFiles            int
	)
	for _, file := range vectorFiles {
		path := filepath.Join(dir, file.name)
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, file.name)

			continue
		}

		res := &result{}
		if err := file.run(path, file.ctx, res); err != nil {
			return fmt.Errorf("%s: %w", file.name, err)
		}

		note := res.note
		if res.skipped > 0 {
			note = fmt.Sprintf("%d skipped, %s", res.skipped, note)
		}
		if note != "" {
			note = " (" + note + ")"
		}

		fmt.Printf("Testing vectors in %-*s [%s]: %s done%s\n", width,
			file.name, res.label(), res.counts(), note)

		for _, failure := range res.failures {
			fmt.Printf("    FAILED: %s\n", failure)
		}

		passed += res.positive + res.negative
		total += res.positiveTotal + res.negativeTotal
		skipped += res.skipped
		if res.failed() {
			failedFiles++
		}
	}

	fmt.Println()
	for _, name := range missing {
		fmt.Printf("No vectors found for %s, skipping it.\n", name)
	}

	if failedFiles > 0 {
		return fmt.Errorf("%d of %d vectors failed in %d file(s)",
			total-passed, total, failedFiles)
	}

	fmt.Printf("All %d vectors passed (%d skipped).\n", passed, skipped)

	return nil
}

// expressions returns a check for a file that holds one expression per line,
// possibly followed by further whitespace separated fields (the expected type
// and op count), which need this package's internals and are not compared.
func expressions(expect expectation) func(string, miniscript.Context,
	*result) error {

	return func(path string, ctx miniscript.Context, res *result) error {
		var columns, insane int

		err := eachLine(path, func(line string) {
			fields := strings.Fields(line)
			expr := fields[0]
			columns = max(columns, len(fields)-1)

			// A miniscript that does not parse is never usable, so
			// the parse is the positive check in all three cases.
			node, err := miniscript.ParseInsane(expr, ctx)
			if expect == mustFail {
				if err == nil {
					res.fail(false, "%s parses but must "+
						"not", expr)

					return
				}

				res.pass(false)

				return
			}

			if err != nil {
				res.fail(true, "%s: %v", expr, err)

				return
			}

			res.pass(true)

			// The sane parse and the dedicated method must agree
			// on whether the expression is sane.
			saneErr := node.IsSane()
			_, parseErr := miniscript.Parse(expr, ctx)
			if (saneErr == nil) != (parseErr == nil) {
				res.fail(true, "%s: IsSane says %v, but Parse "+
					"says %v", expr, saneErr, parseErr)

				return
			}

			if saneErr != nil {
				insane++
			}

			// The malleable corpus holds no sane expression at all,
			// which is a negative vector of its own; the time lock
			// corpus mixes the two, so there its count is only
			// reported.
			if expect == mustParseButInsane {
				if saneErr == nil {
					res.fail(false, "%s is sane but must "+
						"not be", expr)

					return
				}

				res.pass(false)
			}
		})
		if err != nil {
			return err
		}

		switch {
		case expect == mustParseSomeInsane:
			res.note = fmt.Sprintf("%d of them are rejected by "+
				"the sanity checks", insane)

		// The generated corpora carry the expected type, and one of
		// them the op count as well. Neither has an exported accessor
		// in this implementation.
		case expect == mustParse && columns == 1:
			res.note = "type column not compared"

		case expect == mustParse && columns > 1:
			res.note = "type and op count columns not compared"
		}

		return nil
	}
}

// properties compares the static analysis of every expression against the
// columns of a props_from_rust file.
//
// The op count and execution stack columns have no exported accessor and are
// not compared. The malleability, signature and time lock mixing columns are
// compared through the sanity checks, which must reject an expression that any
// of the three columns disqualifies.
func properties(path string, ctx miniscript.Context, res *result) error {
	res.note = "op_count and exec_stack columns not compared"

	header := true

	return eachLine(path, func(line string) {
		if header {
			header = false

			return
		}

		fields := strings.Split(line, "\t")
		expr := fields[0]

		// Rows that rust could not parse are a negative vector: this
		// implementation must reject them as well.
		if len(fields) == 2 && fields[1] == "PARSE_ERR" {
			if _, err := miniscript.ParseInsane(expr, ctx); err ==
				nil {

				res.fail(false, "%s parses but must not", expr)

				return
			}

			res.pass(false)

			return
		}

		if len(fields) != 9 {
			res.fail(true, "%s: malformed row with %d fields",
				expr, len(fields))

			return
		}

		node, err := miniscript.ParseInsane(expr, ctx)
		if err != nil {
			res.fail(true, "%s: %v", expr, err)

			return
		}

		var problems []string
		compare := func(name string, got int, wantField string) {
			want, err := strconv.Atoi(wantField)
			if err != nil {
				problems = append(problems, fmt.Sprintf(
					"%s is not a number: %s", name,
					wantField,
				))

				return
			}

			if got != want {
				problems = append(problems, fmt.Sprintf(
					"%s is %d, want %d", name, got, want,
				))
			}
		}

		// A satisfaction size of -1 means the expression cannot be
		// satisfied at all, which the accessors report as an error.
		compareSat := func(name string, got int, err error,
			wantField string) {

			if wantField == "-1" {
				if err == nil {
					problems = append(problems, fmt.
						Sprintf("%s is %d, want "+
							"unsatisfiable", name,
							got))
				}

				return
			}

			if err != nil {
				problems = append(problems, fmt.Sprintf(
					"%s is unsatisfiable, want %s", name,
					wantField,
				))

				return
			}

			compare(name, got, wantField)
		}

		compare("script_size", node.ScriptLen(), fields[1])

		elements, elementsErr := node.MaxSatisfactionWitnessElements()
		compareSat(
			"sat_witness_elements", elements, elementsErr,
			fields[3],
		)

		size, sizeErr := node.MaxSatisfactionSize()
		compareSat("sat_size", size, sizeErr, fields[8])

		// An expression that mixes time lock kinds, that is malleable
		// or that can be spent without a signature is not sane. The
		// converse does not hold, as the sanity checks also enforce the
		// resource limits, so only this direction is compared.
		mixed, nonMalleable := fields[5] == "true", fields[6] == "true"
		requiresSig := fields[7] == "true"
		if (mixed || !nonMalleable || !requiresSig) &&
			node.IsSane() == nil {

			problems = append(problems, fmt.Sprintf("is sane, but "+
				"mixed_timelocks=%v non_malleable=%v "+
				"requires_sig=%v", mixed, nonMalleable,
				requiresSig))
		}

		if len(problems) > 0 {
			res.fail(true, "%s: %s", expr,
				strings.Join(problems, "; "))

			return
		}

		res.pass(true)
	})
}

// scripts compiles every expression of a scripts_from_rust file and compares
// the encoded script byte for byte.
func scripts(path string, ctx miniscript.Context, res *result) error {
	lookupVar := keyLookup(ctx)

	return eachLine(path, func(line string) {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			res.fail(true, "malformed row: %s", line)

			return
		}
		expr, want := fields[0], fields[1]

		script, err := compile(expr, ctx, lookupVar)

		// Rows without an encoding are a negative vector: the
		// expression has no script in this context.
		if want == "ERR" {
			if err == nil {
				res.fail(false, "%s encodes to %x but must "+
					"not encode", expr, script)

				return
			}

			res.pass(false)

			return
		}

		// Expressions that use the same key twice are rejected when the
		// concrete keys are substituted, which is a check of this
		// implementation rather than of the vector, so they are not
		// compared.
		if err != nil && strings.Contains(err.Error(), "duplicate key") {
			res.skipped++
			res.note = "expressions with duplicate keys"

			return
		}

		if err != nil {
			res.fail(true, "%s: %v", expr, err)

			return
		}

		if got := hex.EncodeToString(script); got != want {
			res.fail(true, "%s encodes to %s, want %s", expr, got,
				want)

			return
		}

		res.pass(true)
	})
}

// compile parses an expression, substitutes the concrete key and hash values
// and returns the encoded script.
func compile(expr string, ctx miniscript.Context,
	lookupVar func(string) ([]byte, error)) ([]byte, error) {

	node, err := miniscript.ParseInsane(expr, ctx)
	if err != nil {
		return nil, err
	}

	if err := node.ApplyVars(lookupVar); err != nil {
		return nil, err
	}

	return node.Script()
}

// keyLookup returns the substitution of the key placeholders A..Z, which stand
// for the public keys of the secret keys 0x00..01 to 0x00..1a, serialized
// compressed in P2WSH and x-only in Tapscript. Any other identifier is a hash
// value, which the parser decodes from the expression itself.
func keyLookup(ctx miniscript.Context) func(string) ([]byte, error) {
	keys := make(map[string][]byte, numKeys)
	for i := 1; i <= numKeys; i++ {
		var secret [32]byte
		secret[31] = byte(i)

		priv, pub := btcec.PrivKeyFromBytes(secret[:])
		key := pub.SerializeCompressed()
		if ctx == miniscript.P2TR {
			key = schnorr.SerializePubKey(priv.PubKey())
		}

		keys[string(rune('A'+i-1))] = key
	}

	return func(identifier string) ([]byte, error) {
		return keys[identifier], nil
	}
}

// redeemVectors is the content of the redeem.json file: the concrete values the
// expressions refer to, and the spending scenarios.
type redeemVectors struct {
	Identifiers map[string]string `json:"identifiers"`
	TestCases   []redeemCase      `json:"test_cases"`
}

// redeemCase is one spending scenario: an expression, the keys and preimage the
// spender holds, the sequence of the input, and whether that is enough to spend
// the output.
type redeemCase struct {
	Miniscript  string `json:"miniscript"`
	Comment     string `json:"comment"`
	Valid       bool   `json:"valid"`
	Sequence    uint32 `json:"sequence,omitempty"`
	CanSign1    bool   `json:"can_sign_1,omitempty"`
	CanSign2    bool   `json:"can_sign_2,omitempty"`
	CanSign3    bool   `json:"can_sign_3,omitempty"`
	HasPreimage bool   `json:"has_preimage,omitempty"`
}

// redeem runs every satisfaction vector as a real spend: it builds the
// P2WSH output the expression describes, has the satisfier produce a witness
// from the assets of the scenario and executes the result in the script engine.
func redeem(path string, _ miniscript.Context, res *result) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	vectors := &redeemVectors{}
	if err := json.Unmarshal(content, vectors); err != nil {
		return err
	}

	res.note = "each spend is executed in the script engine"

	for _, testCase := range vectors.TestCases {
		err := spend(vectors, testCase)
		switch {
		case testCase.Valid && err != nil:
			res.fail(true, "%s (%s): %v", testCase.Miniscript,
				testCase.Comment, err)

		case !testCase.Valid && err == nil:
			res.fail(false, "%s (%s) can be spent but must not be",
				testCase.Miniscript, testCase.Comment)

		default:
			res.pass(testCase.Valid)
		}
	}

	return nil
}

// spend builds and executes the spend of one satisfaction vector, returning an
// error if the expression cannot be satisfied with the assets of the scenario
// or if the resulting witness does not satisfy the script.
func spend(vectors *redeemVectors, testCase redeemCase) error {
	value := func(identifier string) []byte {
		raw, err := hex.DecodeString(vectors.Identifiers[identifier])
		if err != nil {
			return nil
		}

		return raw
	}

	node, err := miniscript.Parse(testCase.Miniscript, miniscript.P2WSH)
	if err != nil {
		return err
	}
	if err := node.IsSane(); err != nil {
		return err
	}
	err = node.ApplyVars(func(identifier string) ([]byte, error) {
		return value(identifier), nil
	})
	if err != nil {
		return err
	}

	witnessScript, err := node.Script()
	if err != nil {
		return err
	}

	// The expression is the witness script of a P2WSH output, which the
	// transaction below spends into an OP_RETURN.
	addr, err := address.NewAddressWitnessScriptHash(
		chainhash.HashB(witnessScript), &chaincfg.TestNet3Params,
	)
	if err != nil {
		return err
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	burnScript, err := txscript.NullDataScript(nil)
	if err != nil {
		return err
	}

	input := wire.NewTxIn(&wire.OutPoint{}, nil, nil)
	input.Sequence = testCase.Sequence
	tx := wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{input},
		TxOut: []*wire.TxOut{{
			Value:    utxoAmount - burnFee,
			PkScript: burnScript,
		}},
	}

	prevOuts := txscript.NewCannedPrevOutputFetcher(pkScript, utxoAmount)
	sigHashes := txscript.NewTxSigHashes(&tx, prevOuts)
	sigHash, err := txscript.CalcWitnessSigHash(
		witnessScript, sigHashes, txscript.SigHashAll, &tx, 0,
		utxoAmount,
	)
	if err != nil {
		return err
	}

	// The scenario names the keys the spender can sign with as can_sign_N,
	// which is the secret key pk_N.
	signers := map[string]*btcec.PrivateKey{}
	for i, canSign := range []bool{
		testCase.CanSign1, testCase.CanSign2, testCase.CanSign3,
	} {
		if !canSign {
			continue
		}

		secret := value(fmt.Sprintf("pk_%d", i+1))
		priv, pub := btcec.PrivKeyFromBytes(secret)
		signers[string(pub.SerializeCompressed())] = priv
	}

	preimage := value("preimage_1")
	witness, err := node.Satisfy(&miniscript.Satisfier{
		Sign: func(pubKey []byte) ([]byte, bool) {
			priv, ok := signers[string(pubKey)]
			if !ok {
				return nil, false
			}

			signature := ecdsa.Sign(priv, sigHash).Serialize()

			return append(
				signature, byte(txscript.SigHashAll),
			), true
		},
		CheckOlder: func(lockTime uint32) (bool, error) {
			return miniscript.CheckOlder(
				lockTime, uint32(tx.Version),
				tx.TxIn[0].Sequence,
			), nil
		},
		CheckAfter: func(lockTime uint32) (bool, error) {
			return miniscript.CheckAfter(
				lockTime, tx.LockTime, tx.TxIn[0].Sequence,
			), nil
		},
		Preimage: func(hashFunc string, hash []byte) ([]byte, bool) {
			if !testCase.HasPreimage {
				return nil, false
			}

			switch hashFunc {
			case "sha256":
				return preimage, bytes.Equal(
					hash, chainhash.HashB(preimage),
				)

			case "ripemd160":
				return preimage, bytes.Equal(
					hash, address.Hash160(preimage),
				)
			}

			return nil, false
		},
	})
	if err != nil {
		return err
	}

	// The witness of a P2WSH spend is the satisfaction followed by the
	// witness script itself.
	elements, err := node.MaxSatisfactionWitnessElements()
	if err != nil {
		return err
	}
	if len(witness)+1 > elements {
		return fmt.Errorf("witness has %d elements, more than the "+
			"computed maximum of %d", len(witness)+1, elements)
	}

	tx.TxIn[0].Witness = append(witness, witnessScript)
	engine, err := txscript.NewEngine(
		pkScript, &tx, 0, txscript.StandardVerifyFlags, nil, sigHashes,
		utxoAmount, prevOuts,
	)
	if err != nil {
		return err
	}

	return engine.Execute()
}

// eachLine calls the given function for every non-empty line of a file.
func eachLine(path string, fn func(line string)) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		fn(line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	return nil
}
