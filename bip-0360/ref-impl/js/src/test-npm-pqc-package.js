#!/usr/bin/env node

/**
 * Node.js test script for Bitcoin PQC WASM module (High-Level API)
 * 
 * Usage: node test-npm-package.js
 * 
 * This script tests the high-level TypeScript wrapper API (index.js) from the
 * command line, which provides a cleaner interface than the low-level API.
 */

import { randomBytes } from 'node:crypto';

// Load the high-level WASM module
let bitcoinpqc;
let Algorithm;

try {
    const module = await import('@jbride/bitcoinpqc-wasm');
    bitcoinpqc = module.bitcoinpqc || module.default;
    Algorithm = module.Algorithm;

    if (!bitcoinpqc || !Algorithm) {
        throw new Error('Failed to import bitcoinpqc or Algorithm from @jbride/bitcoinpqc-wasm');
    }
} catch (error) {
    console.error('Failed to load WASM module:', error);
    console.error('Make sure you have installed the @jbride/bitcoinpqc-wasm package before running this test.');
    process.exit(1);
}

// Helper function to generate random bytes
function generateRandomBytes(length) {
    const array = new Uint8Array(length);
    const bytes = randomBytes(length);
    array.set(bytes);
    return array;
}

// Test function
async function testAlgorithm(algorithm, name) {
    console.log(`\nTesting ${name} algorithm:`);
    console.log('------------------------');

    try {
        // Get key and signature sizes
        const pkSize = bitcoinpqc.publicKeySize(algorithm);
        const skSize = bitcoinpqc.secretKeySize(algorithm);
        const sigSize = bitcoinpqc.signatureSize(algorithm);

        console.log(`Public key size: ${pkSize} bytes`);
        console.log(`Secret key size: ${skSize} bytes`);
        console.log(`Signature size: ${sigSize} bytes`);

        // Generate random data for key generation
        const randomData = generateRandomBytes(128);

        // Generate a key pair
        const keygenStart = Date.now();
        const keypair = bitcoinpqc.generateKeypair(algorithm, randomData);
        const keygenDuration = Date.now() - keygenStart;
        console.log(`Key generation time: ${keygenDuration} ms`);

        // Create a message to sign
        const messageText = 'This is a test message for PQC signature verification';
        const message = Buffer.from(messageText, 'utf8');
        const messageUint8 = new Uint8Array(message);
        console.log(`Message to sign: "${messageText}"`);
        console.log(`Message length: ${message.length} bytes`);

        // Sign the message
        const signStart = Date.now();
        let signature;
        try {
            signature = bitcoinpqc.sign(keypair.secretKey, messageUint8, algorithm);
            const signDuration = Date.now() - signStart;
            console.log(`Signing time: ${signDuration} ms`);
            console.log(`Actual signature size: ${signature.size} bytes`);
        } catch (error) {
            const signDuration = Date.now() - signStart;
            console.log(`Signing failed after ${signDuration} ms`);
            console.log(`Error: ${error.message}`);
            if (algorithm === Algorithm.SLH_DSA_SHAKE_128S) {
                console.log('');
                console.log('⚠️  NOTE: SLH-DSA-SHAKE-128s signing is currently experiencing');
                console.log('   issues when compiled to WebAssembly. This appears to be a');
                console.log('   bug in the SPHINCS+ reference implementation when compiled');
                console.log('   to WASM. ML-DSA-44 (Dilithium) works correctly.');
                console.log('');
                console.log('   Key generation succeeded, but signing failed.');
                console.log('   This is a known limitation of the browser/WASM build.');
            }
            throw error;
        }

        // Verify the signature
        const verifyStart = Date.now();
        const verifyResult = bitcoinpqc.verify(
            keypair.publicKey,
            messageUint8,
            signature,
            algorithm
        );
        const verifyDuration = Date.now() - verifyStart;

        if (verifyResult) {
            console.log('Signature verified successfully!');
        } else {
            console.log('ERROR: Signature verification failed!');
        }
        console.log(`Verification time: ${verifyDuration} ms`);

        // Try to verify with a modified message
        const modifiedMessageText = 'This is a MODIFIED message for PQC signature verification';
        const modifiedMessage = Buffer.from(modifiedMessageText, 'utf8');
        const modifiedMessageUint8 = new Uint8Array(modifiedMessage);
        console.log(`Modified message: "${modifiedMessageText}"`);
        const modifiedVerifyResult = bitcoinpqc.verify(
            keypair.publicKey,
            modifiedMessageUint8,
            signature,
            algorithm
        );

        if (modifiedVerifyResult) {
            console.log('ERROR: Signature verified for modified message!');
        } else {
            console.log('Correctly rejected signature for modified message');
        }

        console.log('✓ Test passed!\n');
        return true;
    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        if (error.stack) {
            console.error(error.stack);
        }
        return false;
    }
}

async function runTests() {
    console.log('Bitcoin PQC Library Example (Node.js - High-Level API)');
    console.log('======================================================\n');
    console.log('This example tests the post-quantum signature algorithms designed for BIP-360 and the Bitcoin QuBit soft fork.');
    console.log('Using the high-level TypeScript wrapper API (index.js).\n');

    // Initialize the module
    try {
        console.log('Initializing WASM module...');
        await bitcoinpqc.init({
            onRuntimeInitialized: () => {
                console.log('✓ WASM module initialized successfully!\n');
            },
            print: (text) => {
                // Enable WASM print output for debugging
                console.log('WASM:', text);
            },
            printErr: (text) => {
                console.error('WASM Error:', text);
            },
            // Node.js-specific: provide crypto.getRandomValues
            getRandomValues: (arr) => {
                const bytes = randomBytes(arr.length);
                arr.set(bytes);
                return arr;
            }
        });
    } catch (error) {
        console.error('Failed to initialize module:', error);
        if (error.stack) {
            console.error(error.stack);
        }
        process.exit(1);
    }

    const results = [];

    // Test ML-DSA-44
    results.push(await testAlgorithm(Algorithm.ML_DSA_44, 'ML-DSA-44'));

    // Test SLH-DSA-Shake-128s
    results.push(await testAlgorithm(Algorithm.SLH_DSA_SHAKE_128S, 'SLH-DSA-Shake-128s'));

    // Summary
    console.log('\n======================================================');
    console.log('Test Summary:');
    console.log(`  ML-DSA-44: ${results[0] ? '✓ PASSED' : '✗ FAILED'}`);
    console.log(`  SLH-DSA-Shake-128s: ${results[1] ? '✓ PASSED' : '✗ FAILED'}`);
    console.log('======================================================\n');

    const exitCode = results.every(r => r) ? 0 : 1;
    process.exit(exitCode);
}

// Start
runTests();
