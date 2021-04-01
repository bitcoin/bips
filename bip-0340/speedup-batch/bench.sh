#!/bin/bash

output_file=$1
cur_dir=$(pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT

cd $temp_dir
git clone git@github.com:jonasnick/secp256k1.git
cd secp256k1
git checkout fd34bfdf06db272f6a435d68de6eb9385d1cec52
./autogen.sh
./configure --enable-experimental --enable-module-schnorrsig
make -j
./bench_schnorrsig > "$cur_dir/$output_file"
