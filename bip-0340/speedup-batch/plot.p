set style line 80 lt rgb "#808080"
set style line 81 lt 0
set style line 81 lt rgb "#808080"
set grid back linestyle 81
set border 3 back linestyle 80
set xtics nomirror
set ytics nomirror
set style line 1 lt rgb "#A00000" lw 2 pt 1
set style line 2 lt rgb "#00A000" lw 2 pt 6
set style line 3 lt rgb "#5060D0" lw 2 pt 2
set style line 4 lt rgb "#F25900" lw 2 pt 9
set key bottom right
set autoscale
unset log
unset label
set xtic auto
set ytic auto
set title "Batch signature verification in libsecp256k1"
set xlabel "Number of signatures (logarithmic)"
set ylabel "Verification time per signature in us"
set grid
set logscale x
set mxtics 10

single_val=system("cat single.dat")
f(x) = a + c*log(x)
fit f(x) "batch.dat" using 1:(single_val/$2) via a, c
# only plot the fitted line for x >= 2
g(x)=((x>=2) ? f(x) : 1/0)
set xrange [1.1:]
set xtics add ("2" 2)
set yrange [0.9:]
set ytics -1,0.1,3
set ylabel "Speedup over single verification"
set term png size 800,600
set output 'speedup-batch.png'
plot    "batch.dat" using 1:(single_val/$2) with points title "" ls 1, g(x) title "log(x) fit" ls 2
