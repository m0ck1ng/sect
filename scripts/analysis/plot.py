import polars as pl
from lifelines import KaplanMeierFitter
from lifelines.statistics import logrank_test
import matplotlib.pyplot as plt


df = pl.read_csv("sched-to-bug-sect.csv")
df = df.unpivot(index=["bug", "tool", "avg.", "stdev."], variable_name = "trial", value_name = "schedules to bug")
df = df.with_columns(pl.col("trial").str.replace("t", "").str.to_integer(), pl.lit(True).alias("found"))

df = df.with_columns(pl.col("bug").fill_null(strategy="forward"))
df = df.drop(["avg.", "stdev."])
df = df.drop_nulls()

tools_to_colors = {
    "Native": "blue",
    "SECT-pos": "purple",
    "SECT-rw": "orange",
    "SECT-pct": "green",
}

vul_nums = {
        "CVE-2023-31083":    "#1: CVE-2023-31083",
        "CVE-2024-42111":    "#2: CVE-2024-42111",
        "CVE-2024-44941":    "#3: CVE-2024-44941",
        "CVE-2024-49903":    "#4: CVE-2024-49903",
        "CVE-2024-50125":    "#5: CVE-2024-50125",
        "CVE-2024-57900":    "#6: CVE-2024-57900",
        "cb2239c1":    "#7: cb2239c1",
        "61179292":    "#8: 61179292",
        "3b9bc84d":    "#9: 3b9bc84d",
        "88b1afbf":    "#10: 88b1afbf",
}

names = {
    "naïve": "Native",
    "sect-pos": "SECT-pos",
    "sect-rw": "SECT-rw",
    "sect-pct": "SECT-pct",
}

for k, v in vul_nums.items():
    df = df.with_columns(pl.col("bug").str.replace(k, v))

for k, v in names.items():
    df = df.with_columns(pl.col("tool").str.replace(k, v))

def plot_bench_survival(ax, df, bench):
    df = df.filter(pl.col("bug") == bench)
    ax.set_title(bench)

    for tool in sorted(df["tool"].unique()):
        d = df.filter(pl.col("tool") == tool).to_pandas()
        # d = d.dropna(subset = ["found"])
        # print(pd.isnull(d))

        kmf = KaplanMeierFitter(label = tool)
        kmf.fit(d["schedules to bug"], d["found"])

        kmf.plot(ax = ax, c=(tools_to_colors[tool]))
        # if "49903" not in bench:
        #    ax.get_legend().remove()
        ax.set(xlabel=None)

df = df.filter(pl.col("bug").str.contains("slip"))
df = df.sort("bug")
n = len(df["bug"].unique())

if n > 1:
    fig, axs = plt.subplots(2, n//2, sharex=False, sharey=True, figsize=(n*2, n-1))
else:
    fig, axs = plt.subplots(1, 1, sharex=False, sharey=True, figsize=(6, 4))

print(df["bug"])
for i, bug in enumerate(sorted(df["bug"].unique())):
    if n > 1:
        plot_bench_survival(axs[i//(n//2)][i%(n//2)], df, bug)
    else:
        plot_bench_survival(axs, df, bug)
        axs.set_title("")

fig.supxlabel("Number of Schedules Explored")
fig.supylabel("Probability bug has not been found")
plt.tight_layout()
plt.savefig("survival.png")

print(df.filter(pl.col("bug").str.contains("31083")).group_by(["bug", "tool"]).max())

exit(0)

df = df.filter(pl.col("bug").str.contains("31083"))
a = df.filter(pl.col("tool") == "SECT-pct")
# b = df.filter(pl.col("tool") == "Native")
b = df.filter(pl.col("tool") == "SECT-rw")

lrt = logrank_test(a["schedules to bug"], b["schedules to bug"], a["found"], b["found"])

print(lrt)
