import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np


def plot_num_recipients():
    pgp, pgph, purbsi, purb = [], [], [], []
    with open("num_recipients.txt") as f:
        Xs = list(map(float, f.readline().split()))
        for x in Xs:
            f.readline()
            pgp.append(mean_and_deviation(f.readline().split()))
            pgph.append(mean_and_deviation(f.readline().split()))
            purbsi.append(mean_and_deviation(f.readline().split()))
            purb.append(mean_and_deviation(f.readline().split()))

    print(pgp, pgph, purbsi, purb)

    plt.loglog(Xs, [i[0] for i in pgp], color='#E9E942', label='PGP', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in pgp], [i[0]+i[1] for i in pgp], facecolor='#FFFDCD')

    plt.loglog(Xs, [i[0] for i in pgph], color='#1B2ACC', label='PGP hidden', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in pgph], [i[0]+i[1] for i in pgph], facecolor='#CDE1FF')

    plt.loglog(Xs, [i[0] for i in purbsi], color='#3CD141', label='PURBs simplified', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in purbsi], [i[0]+i[1] for i in purbsi], facecolor='#D4FFE3')

    plt.loglog(Xs, [i[0] for i in purb], color='#CC4F1B', label='PURBs', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in purb], [i[0]+i[1] for i in purb], facecolor='#FFDFD1')

    # plt.legend(loc='lower right', shadow=True)

    plt.xlim(1, 10000)
    plt.ylim(0.1, 500)
    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.legend()
    plt.ylabel('CPU time, ms')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    # plt.grid(True, which="minor", axis='y')
    plt.axis()
    # plt.show()
    plt.savefig('/Users/knikitin/work/papers/research/purb/figures/num_recipients.eps', format='eps', dpi=1000)


def plot_header_size():
    flat, slack1, slack3, slack10 = [], [], [], []
    with open("header_size.txt") as f:
        Xs = list(map(float, f.readline().split()))
        for x in Xs:
            f.readline()
            flat.append(mean_and_deviation(f.readline().split()))
            slack1.append(mean_and_deviation(f.readline().split()))
            slack3.append(mean_and_deviation(f.readline().split()))
            slack10.append(mean_and_deviation(f.readline().split()))

    print(flat, slack1, slack3, slack10)

    plt.loglog(Xs, [i[0] for i in flat], color='#E9E942', label='Simplified', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in flat], [i[0]+i[1] for i in flat], facecolor='#FFFDCD')

    plt.loglog(Xs, [i[0] for i in slack1], color='#1B2ACC', label='1 Attempt', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in slack1], [i[0]+i[1] for i in slack1], facecolor='#CDE1FF')

    plt.loglog(Xs, [i[0] for i in slack3], color='#CC4F1B', label='3 Attempts', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in slack3], [i[0]+i[1] for i in slack3], facecolor='#FFDFD1')

    plt.loglog(Xs, [i[0] for i in slack10], color='#3CD141', label='10 Attempts', marker='.')
    plt.fill_between(Xs, [i[0]-i[1] for i in slack10], [i[0]+i[1] for i in slack10], facecolor='#D4FFE3')

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.legend()
    plt.ylabel('Header Size, bytes')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    # plt.show()
    plt.savefig('/Users/knikitin/work/papers/research/purb/figures/header_size.eps', format='eps', dpi=1000)


def mean_and_deviation(elems):
    a = np.array(elems)
    a = a.astype(np.float)
    dev = a.std()
    devs = enumerate([abs(elem - dev) for elem in a])
    outlier = max(devs, key=lambda k:k[1])
    a = np.delete(a, outlier[0])
    dev = a.std()
    mean = a.mean()
    return mean, dev


def main():
    mpl.rcParams['text.latex.preamble'] = [r'\usepackage{sansmath}', r'\sansmath']
    mpl.rcParams['font.family'] = 'sans-serif' # ... for regular text
    mpl.rcParams['text.usetex'] = True
    mpl.rcParams['font.sans-serif'] = 'Computer Modern Sans serif'
    mpl.rcParams.update({'font.size': 16})
    # plot_num_recipients()
    plot_header_size()


if __name__ == "__main__":
    main()
