import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

colorbar = ['#EBEBEB', '#FFE5CC', '#CCE5FF']
# colorbar = ['#EBEBEB', "#c2c2ff", "#C5E1C5", "#fffaca", "#ffc2c2", "#9EFFE3"]
colorlog = ['#E2DC27', '#071784', '#077C0F', '#BC220A']
hatches = ['', '//', '.']


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

    plt.loglog(Xs, [i[0] for i in pgp], color='#E2DC27', label='PGP', marker='.')
    plt.fill_between(Xs, [i[0] - i[1] for i in pgp], [i[0] + i[1] for i in pgp], facecolor='#FFFDCD')

    plt.loglog(Xs, [i[0] for i in pgph], color='#071784', label='PGP hidden', marker='d')
    plt.fill_between(Xs, [i[0] - i[1] for i in pgph], [i[0] + i[1] for i in pgph], facecolor='#CDE1FF')

    plt.loglog(Xs, [i[0] for i in purbsi], color='#077C0F', label='PURBs simplified', marker='*')
    plt.fill_between(Xs, [i[0] - i[1] for i in purbsi], [i[0] + i[1] for i in purbsi], facecolor='#D4FFE3')

    plt.loglog(Xs, [i[0] for i in purb], color='#BC220A', label='PURBs', marker='s')
    plt.fill_between(Xs, [i[0] - i[1] for i in purb], [i[0] + i[1] for i in purb], facecolor='#FFDFD1')

    # plt.legend(loc='lower right', shadow=True)

    plt.xlim(1, 10000)
    plt.ylim(0.01, 1000)
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

    plt.loglog(Xs, [i[0] for i in flat], color='#E2DC27', label='Simplified', marker='d')
    plt.fill_between(Xs, [i[0] - i[1] for i in flat], [i[0] + i[1] for i in flat], facecolor='#FFFDCD')

    plt.loglog(Xs, [i[0] for i in slack1], color='#071784', label='1 Attempt', marker='s')
    plt.fill_between(Xs, [i[0] - i[1] for i in slack1], [i[0] + i[1] for i in slack1], facecolor='#CDE1FF')

    plt.loglog(Xs, [i[0] for i in slack3], color='#BC220A', label='3 Attempts', marker='*')
    plt.fill_between(Xs, [i[0] - i[1] for i in slack3], [i[0] + i[1] for i in slack3], facecolor='#FFDFD1')

    plt.loglog(Xs, [i[0] for i in slack10], color='#077C0F', label='10 Attempts', marker='.')
    plt.fill_between(Xs, [i[0] - i[1] for i in slack10], [i[0] + i[1] for i in slack10], facecolor='#D4FFE3')

    plt.tick_params(axis='x', labelsize=16)
    plt.tick_params(axis='y', labelsize=16)
    plt.xlim(1, 4000)
    plt.legend()
    plt.ylabel('Header Size, bytes')
    plt.xlabel('Number of Recipients')
    plt.grid(True, which="major", axis='both')
    plt.axis()
    # plt.show()
    plt.savefig('/Users/knikitin/work/papers/research/purb/figures/header_size.eps', format='eps', dpi=1000)


def plot_encryption():
    N = 21
    # nsuites = [1, 3, 10]
    width = 0.2
    with open("encryption_time.txt") as f:
        # Xs = list(map(float, f.readline().split()))
        Xs = f.readline().split()
        ind = np.arange(1, len(Xs) + 1)
        for ns in range(0, 3):
            genCorner, comShar, other = [], [], []
            f.readline()
            for x in range(0, len(Xs) - ns):
                gl, cl, ol = [], [], []
                for i in range(0, N):
                    g, c, t = map(float, f.readline().split())
                    gl.append(g)
                    cl.append(c)
                    ol.append(t - g - c)

                genCorner.append(mean(gl))
                comShar.append(mean(cl))
                other.append(mean(ol))

            # print(genCorner)
            xloc = [i + (ns - 1) * width for i in ind[ns:]]
            plt.bar(xloc, other, width, color=colorbar[0], hatch=hatches[ns],
                    edgecolor='black', label='Other')
            plt.bar(xloc, genCorner, width, color=colorbar[1], hatch=hatches[ns],
                    bottom=other, edgecolor='black', label='Gen\&encode public')
            plt.bar(xloc, comShar, width, color=colorbar[2], hatch=hatches[ns],
                    bottom=genCorner, edgecolor='black', label='Compute shared')

    plt.xticks(ind, Xs)
    plt.ylabel('CPU time, ms')
    plt.xlabel('Number of Recipients')
    plt.yscale('log')
    plt.grid(True, which="major", axis='y')
    suite1_leg = mpatches.Patch(facecolor='white', edgecolor='black', hatch=hatches[0], label='1 suite')
    suite3_leg = mpatches.Patch(facecolor='white', edgecolor='black', hatch=hatches[1], label='3 suites')
    suite10_leg = mpatches.Patch(facecolor='white', edgecolor='black', hatch=hatches[2], label='10 suites')
    gen_leg = mpatches.Patch(facecolor=colorbar[1], edgecolor='black', label='Gen\&encode public')
    com_leg = mpatches.Patch(facecolor=colorbar[2], edgecolor='black', label='Compute shared')
    oth_leg = mpatches.Patch(facecolor=colorbar[0], edgecolor='black', label='Other')

    plt.legend(handles=[gen_leg, com_leg, oth_leg, suite1_leg, suite3_leg, suite10_leg], ncol=2, fontsize=13,
               labelspacing=0.2, columnspacing=1)
    # plt.show()
    plt.savefig('/Users/knikitin/work/papers/research/purb/figures/enc_time.eps', format='eps', dpi=1000)


def mean_and_deviation(elems):
    a = np.array(elems)
    a = a.astype(np.float)
    dev = a.std()
    devs = enumerate([abs(elem - dev) for elem in a])
    outlier = max(devs, key=lambda k: k[1])
    a = np.delete(a, outlier[0])
    dev = a.std()
    mean = a.mean()
    return mean, dev


def mean(elems):
    a = np.array(elems)
    a = a.astype(np.float)
    dev = a.std()
    devs = enumerate([abs(elem - dev) for elem in a])
    outlier = max(devs, key=lambda k: k[1])
    a = np.delete(a, outlier[0])
    m = a.mean()
    return m


def main():
    mpl.rcParams['text.latex.preamble'] = [r'\usepackage{sansmath}', r'\sansmath']
    # mpl.rcParams['font.family'] = 'sans-serif'  # ... for regular text
    mpl.rcParams['text.usetex'] = True
    # mpl.rcParams['font.sans-serif'] = 'Computer Modern Sans serif'
    mpl.rcParams.update({'font.size': 16})
    plot_num_recipients()
    # plot_header_size()
    # plot_encryption()


if __name__ == "__main__":
    main()
