#!/usr/bin/python3
import numpy as np
import matplotlib.pyplot as plt
PHASES = 15
PHASE_LENGTH = 144
SAMPLES = PHASE_LENGTH * PHASES
AVG_TX = 235
COMPRESSED_NODE_SIZE = 4 + 1 + 1 + 4 + 32 + 4 + 4 + 8 + 8 + 34 + 34 + 33 + 32 + 34
print(COMPRESSED_NODE_SIZE)
MAX_BLOCK_SIZE = 1e6
AVG_INTERVAL = 10*60
TXNS_PER_SEC = 0.5*MAX_BLOCK_SIZE/AVG_TX/AVG_INTERVAL
MAX_MEMPOOL = MAX_BLOCK_SIZE * 100
COMPRESSABLE = 0.05





def get_rate(phase):
    if phase > PHASES/3:
        return 1.25**(2*PHASES/3 - phase) *TXNS_PER_SEC
    else:
        return 1.25**(phase)*TXNS_PER_SEC

def normal():
    np.random.seed(0)
    print("Max Txns Per Sec %f"%TXNS_PER_SEC)
    backlog = 0
    results_unconfirmed = [0]*SAMPLES
    total_time = [0]*SAMPLES
    for phase in range(PHASES):
        for i in range(PHASE_LENGTH*phase, PHASE_LENGTH*(1+phase)):
            block_time = np.random.exponential(AVG_INTERVAL)
            total_time[i] = block_time
            # Equivalent to the sum of one poisson per block time
            # I.E., \sum_1_n Pois(a) = Pois(a*n)
            txns = np.random.poisson(get_rate(phase)* block_time)
            weight = txns*AVG_TX + backlog
            if weight > MAX_BLOCK_SIZE:
                backlog = weight - MAX_BLOCK_SIZE
            else:
                backlog = 0
            results_unconfirmed[i] = backlog/AVG_TX
    return results_unconfirmed, np.cumsum(total_time)/(60*60*24.0)
def compressed(rate_multiplier = 1):
    np.random.seed(0)
    print("Max Txns Per Sec %f"%TXNS_PER_SEC)
    backlog = 0
    secondary_backlog = 0
    results = [0]*SAMPLES
    results_lo_priority = [0]*SAMPLES
    results_confirmed = [0]*SAMPLES
    results_unconfirmed = [0]*SAMPLES
    results_yet_to_spend = [0]*SAMPLES
    total_time = [0]*(SAMPLES)
    for phase in range(PHASES):
        for i in range(PHASE_LENGTH*phase, PHASE_LENGTH*(1+phase)):
            block_time = np.random.exponential(AVG_INTERVAL)
            total_time[i] = block_time
            txns = np.random.poisson(rate_multiplier*get_rate(phase)*block_time)
            postponed = txns * COMPRESSABLE
            weight = (txns-postponed)*AVG_TX + backlog
            secondary_backlog += postponed*133 + postponed*34 # Total extra work
            if weight > MAX_BLOCK_SIZE:
                results_confirmed[i] += MAX_BLOCK_SIZE - AVG_TX
                backlog = weight - MAX_BLOCK_SIZE
            else:
                space = MAX_BLOCK_SIZE - weight
                secondary_backlog = max(secondary_backlog-space, 0)
                backlog = 0
            results_unconfirmed[i] = float(backlog)/AVG_TX
            results_yet_to_spend[i] = secondary_backlog/2/AVG_TX

    return results_unconfirmed, results_yet_to_spend, np.cumsum(total_time)/(60*60*24.0)

DAYS = np.array(range(SAMPLES))/144

def make_patch_spines_invisible(ax):
    ax.set_frame_on(True)
    ax.patch.set_visible(False)
    for sp in ax.spines.values():
        sp.set_visible(False)

if __name__ == "__main__":
    normal_txs, blocktimes_n = normal()
    compressed_txs, unspendable, blocktimes_c1 = compressed()
    compressed_txs2, unspendable2, blocktimes_c2 = compressed(2)

    fig, host = plt.subplots()
    host.set_title("Transaction Compression Performance with %d%% Adoption During Spike"%(100*COMPRESSABLE))
    fig.subplots_adjust(right=0.75)
    par1 = host.twinx()
    par2 = host.twinx()
    par3 = host.twinx()

    par2.spines["right"].set_position(("axes", 1.2))
    make_patch_spines_invisible(par2)
    par2.spines["right"].set_visible(True)

    par3.spines["right"].set_position(("axes", 1.4))
    make_patch_spines_invisible(par3)
    par3.spines["right"].set_visible(True)

    host.set_xlabel("Block Days")

    host.set_ylabel("Transactions per Second")
    p5, = host.plot(range(PHASES), [get_rate(p) for p in range(PHASES)], "k-", label="Transactions Per Second (1x Rate)")
    p6, = host.plot(range(PHASES), [2*get_rate(p) for p in range(PHASES)], "k:", label="Transactions Per Second (2x Rate)")

    host.yaxis.label.set_color(p5.get_color())


    par2.set_ylabel("Unconfirmed Transactions")
    #p1, = par2.plot(DAYS, (-np.array(compressed_txs) + np.array(normal_txs)), "b-.", label = "Mempool Delta")
    p1, = par2.plot(blocktimes_n, normal_txs, "g", label="Mempool without Congestion Control")
    p2, = par2.plot(blocktimes_c1, compressed_txs,"y", label="Mempool with Congestion Control (1x Rate)")
    p3, = par2.plot(blocktimes_c2, compressed_txs2,"m", label="Mempool with Congestion Control (2x Rate)")
    p_full_block, = par2.plot([DAYS[0], DAYS[-1]], [MAX_BLOCK_SIZE/AVG_TX]*2, "b.-", label="Maximum Average Transactions Per Block")

    par2.yaxis.label.set_color(p2.get_color())


    par1.set_ylabel("Confirmed but Pending Transactions")
    p4, = par1.plot(blocktimes_c1, unspendable2, "c", label="Congestion Control Pending (2x Rate)")
    p4, = par1.plot(blocktimes_c2, unspendable, "r", label="Congestion Control Pending (1x Rate)")
    par1.yaxis.label.set_color(p4.get_color())




    lines = [p1, p2, p3, p4, p5, p6, p_full_block]
    host.legend(lines, [l.get_label() for l in lines])

    plt.show()
