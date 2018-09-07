// This program connects to your local btcd and generates test vectors for
// 5 blocks and collision space sizes of 1-32 bits. Change the RPC cert path
// and credentials to run on your system. The program assumes you're running
// a btcd with cfilter support, which mainline btcd doesn't have; in order to
// circumvent this assumption, comment out the if block that checks for
// filter size of DefaultP.

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs/builder"
	"github.com/davecgh/go-spew/spew"
)

var (
	// testBlockHeights are the heights of the blocks to include in the test
	// vectors. Any new entries must be added in sorted order.
	testBlockHeights = []testBlockCase{
		{0, "Genesis block"},
		{2, ""},
		{3, ""},
		{49291, "Tx pays to empty output script"},
		{180480, "Tx spends from empty output script"},
		{926485, "Duplicate pushdata 913bcc2be49cb534c20474c4dee1e9c4c317e7eb"},
		{987876, "Coinbase tx has unparseable output script"},
		{1263442, "Includes witness data"},
	}

	defaultBtcdDir         = btcutil.AppDataDir("btcd", false)
	defaultBtcdRPCCertFile = filepath.Join(defaultBtcdDir, "rpc.cert")
)

const (
	fp = 19
)

type testBlockCase struct {
	height  uint32
	comment string
}

type JSONTestWriter struct {
	writer          io.Writer
	firstRowWritten bool
}

func NewJSONTestWriter(writer io.Writer) *JSONTestWriter {
	return &JSONTestWriter{writer: writer}
}

func (w *JSONTestWriter) WriteComment(comment string) error {
	return w.WriteTestCase([]interface{}{comment})
}

func (w *JSONTestWriter) WriteTestCase(row []interface{}) error {
	var err error
	if w.firstRowWritten {
		_, err = io.WriteString(w.writer, ",\n")
	} else {
		_, err = io.WriteString(w.writer, "[\n")
		w.firstRowWritten = true
	}
	if err != nil {
		return err
	}

	rowBytes, err := json.Marshal(row)
	if err != nil {
		return err
	}

	_, err = w.writer.Write(rowBytes)
	return err
}

func (w *JSONTestWriter) Close() error {
	if !w.firstRowWritten {
		return nil
	}

	_, err := io.WriteString(w.writer, "\n]\n")
	return err
}

func fetchPrevOutputScripts(client *rpcclient.Client, block *wire.MsgBlock) ([][]byte, error) {
	var prevScripts [][]byte

	txCache := make(map[chainhash.Hash]*wire.MsgTx)
	for _, tx := range block.Transactions {
		if blockchain.IsCoinBaseTx(tx) {
			continue
		}

		for _, txIn := range tx.TxIn {
			prevOp := txIn.PreviousOutPoint

			tx, ok := txCache[prevOp.Hash]
			if !ok {
				originTx, err := client.GetRawTransaction(
					&prevOp.Hash,
				)
				if err != nil {
					return nil, fmt.Errorf("unable to get "+
						"txid=%v: %v", prevOp.Hash, err)
				}

				txCache[prevOp.Hash] = originTx.MsgTx()

				tx = originTx.MsgTx()
			}

			index := prevOp.Index

			prevScripts = append(
				prevScripts, tx.TxOut[index].PkScript,
			)
		}
	}

	return prevScripts, nil
}

func main() {
	var (
		writerFile      *JSONTestWriter
		prevBasicHeader chainhash.Hash
	)
	fName := fmt.Sprintf("testnet-%02d.json", fp)
	file, err := os.Create(fName)
	if err != nil {
		fmt.Println("Error creating output file: ", err.Error())
		return
	}
	defer file.Close()

	writer := &JSONTestWriter{
		writer: file,
	}
	defer writer.Close()

	err = writer.WriteComment("Block Height,Block Hash,Block," +
		"[Prev Output Scripts for Block],Previous Basic Header," +
		"Basic Filter,Basic Header,Notes")
	if err != nil {
		fmt.Println("Error writing to output file: ", err.Error())
		return
	}

	writerFile = writer

	cert, err := ioutil.ReadFile(defaultBtcdRPCCertFile)
	if err != nil {
		fmt.Println("Couldn't read RPC cert: ", err.Error())
		return
	}

	conf := rpcclient.ConnConfig{
		Host:         "127.0.0.1:18334",
		Endpoint:     "ws",
		User:         "kek",
		Pass:         "kek",
		Certificates: cert,
	}
	client, err := rpcclient.New(&conf, nil)
	if err != nil {
		fmt.Println("Couldn't create a new client: ", err.Error())
		return
	}

	var testBlockIndex int
	for height := 0; testBlockIndex < len(testBlockHeights); height++ {
		blockHash, err := client.GetBlockHash(int64(height))
		if err != nil {
			fmt.Println("Couldn't get block hash: ", err.Error())
			return
		}

		block, err := client.GetBlock(blockHash)
		if err != nil {
			fmt.Println("Couldn't get block hash: ", err.Error())
			return
		}

		var blockBuf bytes.Buffer
		err = block.Serialize(&blockBuf)
		if err != nil {
			fmt.Println("Error serializing block to buffer: ", err.Error())
			return
		}
		blockBytes := blockBuf.Bytes()

		prevOutputScripts, err := fetchPrevOutputScripts(client, block)
		if err != nil {
			fmt.Println("Couldn't fetch prev output scipts: ", err)
			return
		}

		basicFilter, err := builder.BuildBasicFilter(block, prevOutputScripts)
		if err != nil {
			fmt.Println("Error generating basic filter: ", err.Error())
			return
		}
		basicHeader, err := builder.MakeHeaderForFilter(basicFilter, prevBasicHeader)
		if err != nil {
			fmt.Println("Error generating header for filter: ", err.Error())
			return
		}

		// We'll now ensure that we've constructed the same filter as
		// the chain server we're fetching blocks form.
		filter, err := client.GetCFilter(
			blockHash, wire.GCSFilterRegular,
		)
		if err != nil {
			fmt.Println("Error getting basic filter: ",
				err.Error())
			return
		}

		nBytes, err := basicFilter.NBytes()
		if err != nil {
			fmt.Println("Couldn't get NBytes(): ", err)
			return
		}
		if !bytes.Equal(filter.Data, nBytes) {
			// Don't error on empty filters
			fmt.Printf("basic filter doesn't match: generated "+
				"%x, rpc returns %x, block %v", nBytes,
				filter.Data, spew.Sdump(block))
			return
		}

		header, err := client.GetCFilterHeader(
			blockHash, wire.GCSFilterRegular,
		)
		if err != nil {
			fmt.Println("Error getting basic header: ", err.Error())
			return
		}
		if !bytes.Equal(header.PrevFilterHeader[:], basicHeader[:]) {
			fmt.Println("Basic header doesn't match!")
			return
		}

		if height%1000 == 0 {
			fmt.Printf("Verified height %v against server\n", height)
		}

		if uint32(height) == testBlockHeights[testBlockIndex].height {
			var bfBytes []byte
			bfBytes, err = basicFilter.NBytes()
			if err != nil {
				fmt.Println("Couldn't get NBytes(): ", err)
				return
			}

			prevScriptStrings := make([]string, len(prevOutputScripts))
			for i, prevScript := range prevOutputScripts {
				prevScriptStrings[i] = hex.EncodeToString(prevScript)
			}

			row := []interface{}{
				height,
				blockHash.String(),
				hex.EncodeToString(blockBytes),
				prevScriptStrings,
				prevBasicHeader.String(),
				hex.EncodeToString(bfBytes),
				basicHeader.String(),
				testBlockHeights[testBlockIndex].comment,
			}
			err = writerFile.WriteTestCase(row)
			if err != nil {
				fmt.Println("Error writing test case to output: ", err.Error())
				return
			}
		}

		prevBasicHeader = basicHeader

		if uint32(height) == testBlockHeights[testBlockIndex].height {
			testBlockIndex++
		}
	}
}
