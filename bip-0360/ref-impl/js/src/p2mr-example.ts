// src/p2mr-example.ts
// Example demonstrating P2MR (Pay-to-Taproot-Script-Hash) address construction

import { payments } from '@jbride/bitcoinjs-lib';
import * as bitcoinCrypto from '@jbride/bitcoinjs-lib/src/crypto';
import * as bscript from '@jbride/bitcoinjs-lib/src/script';
import type { Taptree } from '@jbride/bitcoinjs-lib/src/types';
import ECPairFactory, { type ECPairInterface } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import { randomBytes } from 'crypto';

const { p2mr } = payments;

// Initialize ECPair with the ECC library
const ECPair = ECPairFactory(ecc);

// Create a secure RNG function
const rng = (size: number) => randomBytes(size);

function signAndVerify(
  keyPair: ECPairInterface,
  xOnlyPubkey: Uint8Array,
  message: Buffer,
) {
  const hash = Buffer.from(bitcoinCrypto.hash256(message));
  const schnorrSignature = Buffer.from(keyPair.signSchnorr(hash));
  const signatureWithSighashDefault = Buffer.concat([schnorrSignature, Buffer.from([0x00])]);
  const verified = keyPair.verifySchnorr(hash, schnorrSignature);

  return {
    message,
    hash,
    signature: schnorrSignature,
    signatureWithSighashDefault,
    verified,
  };
}

/**
 * Example 1: Construct a P2MR address from a script tree with a single leaf
 * This is the simplest case - a script tree containing one script.
 */
function example1_simpleScriptTree() {
  console.log('=== Example 1: P2MR from simple script tree ===');
  
  // Generate a key pair
  const keyPair = ECPair.makeRandom({ rng });
  const pubkey = keyPair.publicKey;
  const xOnlyPubkey = ecc.xOnlyPointFromPoint(pubkey);
  
  // Compile the script: x-only pubkey OP_CHECKSIG (BIP342 Schnorr signature)
  const script = bscript.compile([Buffer.from(xOnlyPubkey), bscript.OPS.OP_CHECKSIG]);
  
  // Create a script tree with one leaf
  const scriptTree = {
    output: script,
  };
  
  // Construct the P2MR payment
  const payment = p2mr({
    scriptTree: scriptTree,
  });
  
  console.log('Generated compressed pubkey:', pubkey.toString('hex'));
  console.log('X-only pubkey:', Buffer.from(xOnlyPubkey).toString('hex'));
  console.log('Script tree:', { output: bscript.toASM(script) });
  console.log('P2MR Address:', payment.address);
  console.log('Output script:', bscript.toASM(payment.output!));
  console.log('Merkle root hash:', payment.hash ? Buffer.from(payment.hash).toString('hex') : undefined);
  const message = Buffer.from('P2MR demo - example 1', 'utf8');
  const result = signAndVerify(keyPair, xOnlyPubkey, message);

  console.log('Message:', result.message.toString('utf8'));
  console.log('Hash256(message):', result.hash.toString('hex'));
  console.log('Schnorr signature (64-byte):', result.signature.toString('hex'));
  console.log('Signature + default sighash (65-byte witness element):', result.signatureWithSighashDefault.toString('hex'));
  console.log('Signature valid:', result.verified);
  console.log('Witness stack for spend:', [result.signatureWithSighashDefault.toString('hex'), bscript.toASM(script)]);
  console.log();
}

/**
 * Example 2: Construct a P2MR address from a script tree with multiple leaves
 * This demonstrates a more complex script tree structure.
 */
function example2_multiLeafScriptTree() {
  console.log('=== Example 2: P2MR from multi-leaf script tree ===');
  
  // Generate two different key pairs for the leaves
  const keyPair1 = ECPair.makeRandom({ rng });
  const keyPair2 = ECPair.makeRandom({ rng });
  const pubkey1 = keyPair1.publicKey;
  const pubkey2 = keyPair2.publicKey;
  const xOnlyPubkey1 = ecc.xOnlyPointFromPoint(pubkey1);
  const xOnlyPubkey2 = ecc.xOnlyPointFromPoint(pubkey2);
  
  const script1 = bscript.compile([Buffer.from(xOnlyPubkey1), bscript.OPS.OP_CHECKSIG]);
  const script2 = bscript.compile([Buffer.from(xOnlyPubkey2), bscript.OPS.OP_CHECKSIG]);
  
  // Create a script tree with two leaves (array of two leaf objects)
  const scriptTree: Taptree = [
    { output: script1 },
    { output: script2 },
  ];
  
  // Construct the P2MR payment
  const payment = p2mr({
    scriptTree: scriptTree,
  });
  
  console.log('Generated compressed public keys:');
  console.log('  Pubkey 1:', pubkey1.toString('hex'));
  console.log('  Pubkey 2:', pubkey2.toString('hex'));
  console.log('X-only pubkeys:');
  console.log('  X-only 1:', Buffer.from(xOnlyPubkey1).toString('hex'));
  console.log('  X-only 2:', Buffer.from(xOnlyPubkey2).toString('hex'));
  console.log('Script tree leaves:');
  console.log('  Leaf 1:', bscript.toASM(script1));
  console.log('  Leaf 2:', bscript.toASM(script2));
  console.log('P2MR Address:', payment.address);
  console.log('Output script:', bscript.toASM(payment.output!));
  console.log('Merkle root hash:', payment.hash ? Buffer.from(payment.hash).toString('hex') : undefined);
  const message1 = Buffer.from('P2MR demo - example 2 leaf 1', 'utf8');
  const message2 = Buffer.from('P2MR demo - example 2 leaf 2', 'utf8');
  const result1 = signAndVerify(keyPair1, xOnlyPubkey1, message1);
  const result2 = signAndVerify(keyPair2, xOnlyPubkey2, message2);

  console.log('Leaf 1 signature info:');
  console.log('  Message:', result1.message.toString('utf8'));
  console.log('  Hash256(message):', result1.hash.toString('hex'));
  console.log('  Schnorr signature (64-byte):', result1.signature.toString('hex'));
  console.log('  Signature + default sighash (65-byte):', result1.signatureWithSighashDefault.toString('hex'));
  console.log('  Signature valid:', result1.verified);
  console.log('  Witness stack:', [result1.signatureWithSighashDefault.toString('hex'), bscript.toASM(script1)]);

  console.log('Leaf 2 signature info:');
  console.log('  Message:', result2.message.toString('utf8'));
  console.log('  Hash256(message):', result2.hash.toString('hex'));
  console.log('  Schnorr signature (64-byte):', result2.signature.toString('hex'));
  console.log('  Signature + default sighash (65-byte):', result2.signatureWithSighashDefault.toString('hex'));
  console.log('  Signature valid:', result2.verified);
  console.log('  Witness stack:', [result2.signatureWithSighashDefault.toString('hex'), bscript.toASM(script2)]);
  console.log();
}

/**
 * Example 4: Construct a P2MR address from a hash and redeem script
 * This demonstrates creating a P2MR when you have the hash directly.
 */
function example3_fromHashAndRedeem() {
  console.log('=== Example 3: P2MR from hash and redeem script ===');
  
  // Generate a key pair
  const keyPair = ECPair.makeRandom({ rng });
  const pubkey = keyPair.publicKey;
  const xOnlyPubkey = ecc.xOnlyPointFromPoint(pubkey);
  const redeemScript = bscript.compile([Buffer.from(xOnlyPubkey), bscript.OPS.OP_CHECKSIG]);
  
  // Use a known hash (from test fixtures)
  const hash = Buffer.from(
    'b424dea09f840b932a00373cdcdbd25650b8c3acfe54a9f4a641a286721b8d26',
    'hex',
  );
  
  // Construct the P2MR payment
  const payment = p2mr({
    hash: hash,
    redeem: {
      output: redeemScript,
    },
  });
  
  console.log('Generated compressed pubkey:', pubkey.toString('hex'));
  console.log('X-only pubkey:', Buffer.from(xOnlyPubkey).toString('hex'));
  console.log('Redeem script:', bscript.toASM(redeemScript));
  console.log('Hash:', hash.toString('hex'));
  console.log('P2MR Address:', payment.address);
  console.log('Output script:', bscript.toASM(payment.output!));
  const message = Buffer.from('P2MR demo - example 3', 'utf8');
  const result = signAndVerify(keyPair, xOnlyPubkey, message);

  console.log('Message:', result.message.toString('utf8'));
  console.log('Hash256(message):', result.hash.toString('hex'));
  console.log('Schnorr signature (64-byte):', result.signature.toString('hex'));
  console.log('Signature + default sighash (65-byte):', result.signatureWithSighashDefault.toString('hex'));
  console.log('Signature valid:', result.verified);
  console.log('Witness stack:', [result.signatureWithSighashDefault.toString('hex'), bscript.toASM(redeemScript)]);
  console.log();
}

// Run all examples
console.log('P2MR Address Construction Examples\n');
console.log('=====================================\n');

example1_simpleScriptTree();
example2_multiLeafScriptTree();
example3_fromHashAndRedeem();

console.log('=====================================');
console.log('All examples completed!');
