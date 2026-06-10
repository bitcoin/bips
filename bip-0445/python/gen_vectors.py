#!/usr/bin/env python3

import glob
import os
import sys

from generators.det_sign import generate_det_sign_vectors
from generators.nonce import (
    generate_nonce_agg_vectors,
    generate_nonce_gen_vectors,
)
from generators.sig_agg import generate_sig_agg_vectors
from generators.sign_verify import generate_sign_verify_vectors
from generators.tweak import generate_tweak_vectors


def create_vectors_directory():
    os.makedirs("vectors", exist_ok=True)
    for f in glob.glob("vectors/*.json"):
        os.remove(f)


def run_gen_vectors(test_name, test_func):
    max_len = 30
    test_name = test_name.ljust(max_len, ".")
    print(f"Running {test_name}...", end="", flush=True)
    try:
        test_func()
        print("Done!")
    except Exception as e:
        print(f"Failed :'(\nError: {e}")


def main():
    create_vectors_directory()

    run_gen_vectors("generate_nonce_gen_vectors", generate_nonce_gen_vectors)
    run_gen_vectors("generate_nonce_agg_vectors", generate_nonce_agg_vectors)
    run_gen_vectors("generate_sign_verify_vectors", generate_sign_verify_vectors)
    run_gen_vectors("generate_tweak_vectors", generate_tweak_vectors)
    run_gen_vectors("generate_det_sign_vectors", generate_det_sign_vectors)
    run_gen_vectors("generate_sig_agg_vectors", generate_sig_agg_vectors)
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
