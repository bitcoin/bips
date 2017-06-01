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
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcd/chaincfg/chainhash"
	"github.com/roasbeef/btcd/rpcclient"
	"github.com/roasbeef/btcd/wire"
	"github.com/roasbeef/btcutil/gcs"
	"github.com/roasbeef/btcutil/gcs/builder"
)

func main() {
	err := os.Mkdir("gcstestvectors", os.ModeDir|0755)
	if err != nil { // Don't overwrite existing output if any
		fmt.Println("Couldn't create directory: ", err)
		return
	}
	files := make([]*os.File, 33)
	prevBasicHeaders := make([]chainhash.Hash, 33)
	prevExtHeaders := make([]chainhash.Hash, 33)
	for i := 1; i <= 32; i++ { // Min 1 bit of collision space, max 32
		var blockBuf bytes.Buffer
		fName := fmt.Sprintf("gcstestvectors/testnet-%02d.csv", i)
		file, err := os.Create(fName)
		if err != nil {
			fmt.Println("Error creating CSV file: ", err.Error())
			return
		}
		_, err = file.WriteString("Block Height,Block Hash,Block,Previous Basic Header,Previous Ext Header,Basic Filter,Ext Filter,Basic Header,Ext Header\n")
		if err != nil {
			fmt.Println("Error writing to CSV file: ", err.Error())
			return
		}
		files[i] = file
		basicFilter, err := buildBasicFilter(
			chaincfg.TestNet3Params.GenesisBlock, uint8(i))
		if err != nil && err != gcs.ErrNoData {
			fmt.Println("Error generating basic filter: ", err.Error())
			return
		}
		prevBasicHeaders[i] = builder.MakeHeaderForFilter(basicFilter,
			chaincfg.TestNet3Params.GenesisBlock.Header.PrevBlock)
		if basicFilter == nil {
			basicFilter = &gcs.Filter{}
		}
		extFilter, err := buildExtFilter(
			chaincfg.TestNet3Params.GenesisBlock, uint8(i))
		if err != nil && err != gcs.ErrNoData {
			fmt.Println("Error generating ext filter: ", err.Error())
			return
		}
		prevExtHeaders[i] = builder.MakeHeaderForFilter(extFilter,
			chaincfg.TestNet3Params.GenesisBlock.Header.PrevBlock)
		if extFilter == nil {
			extFilter = &gcs.Filter{}
		}
		err = chaincfg.TestNet3Params.GenesisBlock.Serialize(&blockBuf)
		if err != nil {
			fmt.Println("Error serializing block to buffer: ", err.Error())
			return
		}
		var bfBytes []byte
		var efBytes []byte
		if basicFilter.N() > 0 {
			bfBytes = basicFilter.NBytes()
		}
		if extFilter.N() > 0 { // Exclude special case for block 987876
			efBytes = extFilter.NBytes()
		}
		err = writeCSVRow(
			file,
			0, // Height
			*chaincfg.TestNet3Params.GenesisHash,
			blockBuf.Bytes(),
			chaincfg.TestNet3Params.GenesisBlock.Header.PrevBlock,
			chaincfg.TestNet3Params.GenesisBlock.Header.PrevBlock,
			bfBytes,
			efBytes,
			prevBasicHeaders[i],
			prevExtHeaders[i],
		)
		if err != nil {
			fmt.Println("Error writing to CSV file: ", err.Error())
			return
		}
	}
	cert, err := ioutil.ReadFile(
		path.Join(os.Getenv("HOME"), "/.btcd/rpc.cert"))
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
	for height := 1; height < 988000; height++ {
		fmt.Printf("Height: %d\n", height)
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
		for i := 1; i <= 32; i++ {
			basicFilter, err := buildBasicFilter(block, uint8(i))
			if err != nil && err != gcs.ErrNoData {
				fmt.Println("Error generating basic filter: ", err.Error())
				return
			}
			basicHeader := builder.MakeHeaderForFilter(basicFilter,
				prevBasicHeaders[i])
			if basicFilter == nil {
				basicFilter = &gcs.Filter{}
			}
			extFilter, err := buildExtFilter(block, uint8(i))
			if err != nil && err != gcs.ErrNoData {
				fmt.Println("Error generating ext filter: ", err.Error())
				return
			}
			extHeader := builder.MakeHeaderForFilter(extFilter,
				prevExtHeaders[i])
			if extFilter == nil {
				extFilter = &gcs.Filter{}
			}
			if i == builder.DefaultP { // This is the default filter size so we can check against the server's info
				filter, err := client.GetCFilter(blockHash, wire.GCSFilterRegular)
				if err != nil {
					fmt.Println("Error getting basic filter: ", err.Error())
					return
				}
				if !bytes.Equal(filter.Data, basicFilter.NBytes()) &&
					(len(filter.Data) != 0 || len(basicFilter.NBytes()) != 4) {
					// Don't error on empty filters
					fmt.Println("Basic filter doesn't match!")
					return
				}
				filter, err = client.GetCFilter(blockHash, wire.GCSFilterExtended)
				if err != nil {
					fmt.Println("Error getting extended filter: ", err.Error())
					return
				}
				if !bytes.Equal(filter.Data, extFilter.NBytes()) &&
					(len(filter.Data) != 0 || len(extFilter.NBytes()) != 4) {
					fmt.Println("Extended filter doesn't match!")
					return
				}
				header, err := client.GetCFilterHeader(blockHash, wire.GCSFilterRegular)
				if err != nil {
					fmt.Println("Error getting basic header: ", err.Error())
					return
				}
				if !bytes.Equal(header.HeaderHashes[0][:], basicHeader[:]) {
					fmt.Println("Basic header doesn't match!")
					return
				}
				header, err = client.GetCFilterHeader(blockHash, wire.GCSFilterExtended)
				if err != nil {
					fmt.Println("Error getting extended header: ", err.Error())
					return
				}
				if !bytes.Equal(header.HeaderHashes[0][:], extHeader[:]) {
					fmt.Println("Extended header doesn't match!")
					return
				}
				fmt.Println("Verified against server")
			}
			switch height {
			case 1, 2, 3, 926485, 987876: // Blocks for test cases
				var bfBytes []byte
				var efBytes []byte
				if basicFilter.N() > 0 {
					bfBytes = basicFilter.NBytes()
				}
				if extFilter.N() > 0 { // Exclude special case for block 987876
					efBytes = extFilter.NBytes()
				}
				writeCSVRow(
					files[i],
					height,
					*blockHash,
					blockBytes,
					prevBasicHeaders[i],
					prevExtHeaders[i],
					bfBytes,
					efBytes,
					basicHeader,
					extHeader)
			}
			prevBasicHeaders[i] = basicHeader
			prevExtHeaders[i] = extHeader
		}
	}
}

// writeCSVRow writes a test vector to a CSV file.
func writeCSVRow(file *os.File, height int, blockHash chainhash.Hash,
	blockBytes []byte, prevBasicHeader, prevExtHeader chainhash.Hash,
	basicFilter, extFilter []byte, basicHeader, extHeader chainhash.Hash) error {
	row := fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s,%s\n",
		height,
		blockHash.String(),
		hex.EncodeToString(blockBytes),
		prevBasicHeader.String(),
		prevExtHeader.String(),
		hex.EncodeToString(basicFilter),
		hex.EncodeToString(extFilter),
		basicHeader.String(),
		extHeader.String(),
	)
	_, err := file.WriteString(row)
	if err != nil {
		return err
	}
	return nil
}

// buildBasicFilter builds a basic GCS filter from a block. A basic GCS filter
// will contain all the previous outpoints spent within a block, as well as the
// data pushes within all the outputs created within a block. p is specified as
// an argument in order to create test vectors with various values for p.
func buildBasicFilter(block *wire.MsgBlock, p uint8) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHashP(&blockHash, p)

	// If the filter had an issue with the specified key, then we force it
	// to bubble up here by calling the Key() function.
	_, err := b.Key()
	if err != nil {
		return nil, err
	}

	// In order to build a basic filter, we'll range over the entire block,
	// adding the outpoint data as well as the data pushes within the
	// pkScript.
	for i, tx := range block.Transactions {
		// First we'll compute the bash of the transaction and add that
		// directly to the filter.
		txHash := tx.TxHash()
		b.AddHash(&txHash)

		// Skip the inputs for the coinbase transaction
		if i != 0 {
			// Each each txin, we'll add a serialized version of
			// the txid:index to the filters data slices.
			for _, txIn := range tx.TxIn {
				b.AddOutPoint(txIn.PreviousOutPoint)
			}
		}

		// For each output in a transaction, we'll add each of the
		// individual data pushes within the script.
		for _, txOut := range tx.TxOut {
			b.AddScript(txOut.PkScript)
		}
	}

	return b.Build()
}

// buildExtFilter builds an extended GCS filter from a block. An extended
// filter supplements a regular basic filter by include all the _witness_ data
// found within a block. This includes all the data pushes within any signature
// scripts as well as each element of an input's witness stack. Additionally,
// the _hashes_ of each transaction are also inserted into the filter. p is
// specified as an argument in order to create test vectors with various values
// for p.
func buildExtFilter(block *wire.MsgBlock, p uint8) (*gcs.Filter, error) {
	blockHash := block.BlockHash()
	b := builder.WithKeyHashP(&blockHash, p)

	// If the filter had an issue with the specified key, then we force it
	// to bubble up here by calling the Key() function.
	_, err := b.Key()
	if err != nil {
		return nil, err
	}

	// In order to build an extended filter, we add the hash of each
	// transaction as well as each piece of witness data included in both
	// the sigScript and the witness stack of an input.
	for i, tx := range block.Transactions {
		// Skip the inputs for the coinbase transaction
		if i != 0 {
			// Next, for each input, we'll add the sigScript (if
			// it's present), and also the witness stack (if it's
			// present)
			for _, txIn := range tx.TxIn {
				if txIn.SignatureScript != nil {
					b.AddScript(txIn.SignatureScript)
				}

				if len(txIn.Witness) != 0 {
					b.AddWitness(txIn.Witness)
				}
			}
		}
	}

	return b.Build()
}
