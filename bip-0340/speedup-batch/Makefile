bench_output.txt: bench.sh
	SECP256K1_BENCH_ITERS=100000 ./bench.sh bench_output.txt

batch.dat: bench_output.txt
	cat bench_output.txt | grep -v "schnorrsig_batch_verify_1" | awk 'match($$0, /schnorrsig_batch_verify_(.*):.*avg (.*)us /, a) {print a[1] " " a[2]}' > batch.dat

single.dat: bench_output.txt
	cat bench_output.txt | awk 'match($$0, /schnorrsig_verify:.*avg (.*)us /, a) {print a[1]}' > single.dat

speedup-batch.png: batch.dat single.dat plot.p
	gnuplot plot.p
