import subprocess as sp
import polars as pl
import seaborn as sns
import matplotlib
import matplotlib.pyplot as plt
from tqdm import tqdm
import os
import glob
import re

KERNEL_VERSION = "6.14-rc6" 
current_trial_name = ""

def get_cat(desc):
    tokens = ["WARNING", "SYZFATAL", "INFO", "BUG", "KASAN", "KCSAN", "UBSAN"]
    for token in tokens:
        if desc.strip().startswith(token):
            return token
    return "OTHER"

def count_max_async(log_paths):
    min_max_async = 99999;
    worst_best_index = 99999;
    for path in log_paths:
        with open(path, 'r', encoding='latin-1') as f:
            s = f.read()
            progs = s.split(" executing program ")
            counts = [prog.count("(async)") for prog in progs]
            max_async = max(counts) 
            min_max_async = min(min_max_async, max_async)

            if max_async >= 2:
                max_async_index = -1*counts[::-1].index(max_async) - 1
                worst_best_index = min(worst_best_index, max_async_index)

    if min_max_async == 99999:
        min_max_async = None
    if worst_best_index == 99999:
        worst_best_index = None

    return (min_max_async, worst_best_index)

def get_current_data():

    p = sp.run("find . | grep description", shell=True, capture_output=True)

    paths = p.stdout.decode("utf-8")
    paths = paths.splitlines()

    df = []
    for path in tqdm(paths):
        (w, exp, tool_trial, x, crash_id, y) = path.split('/')
        tool_trial = tool_trial.replace(f"_{KERNEL_VERSION}", "")
        (tool, trial) = tool_trial.rsplit('_', 1)
        trial = int(trial.replace('t', ''))
        tool = f"rand-preempt-{tool}"

        report_glob = path.replace("description", "report*")
        reports = glob.glob(report_glob)
        num_reports = len(reports)

        log_glob = path.replace("description", "log*")
        log_paths = glob.glob(log_glob)
        (min_max_async, best_worst_index) = count_max_async(log_paths)

        with open(path, 'r') as f:
            desc = f.read().strip()
            cat = get_cat(desc)
            reduced_desc = desc
            if cat is not None:
                reduced_desc = desc.replace(cat, '')
                reduced_desc = re.sub('^:', '', reduced_desc, 1).strip()

            bug = None
            loc = None
            if reduced_desc.startswith("in "):
                loc = reduced_desc.replace("in ", "", 1).strip()
            vals = reduced_desc.split(" in ")
            if len(vals) == 2:
                (bug, loc) = vals
                bug = bug.strip()
                loc = loc.strip()



            df.append((tool, trial, crash_id, cat, bug, loc, desc, exp, num_reports,min_max_async, best_worst_index))

    df = pl.DataFrame(df, orient="row", schema=("tool", "trial", "crash_id", "cat", "bug", "loc", "desc", "exp", "num_reports", "min_asyncs_in_log", "max_programs_from_end_of_log_to_asyncs"))
    return df

if os.path.exists("current-cache.csv"):
    print("using current-cache.csv...")
    df = pl.read_csv("current-cache.csv")
else:
    df = get_current_data()
    df.write_csv("current-cache.csv")

if os.path.exists("historical.csv"):
    df2 = pl.read_csv("historical.csv")
    df = pl.concat([df, df2], how="vertical_relaxed")
    df = df.with_columns(
        pl.col("min_asyncs_in_log").cast(pl.Int32),
        pl.col("max_programs_from_end_of_log_to_asyncs").cast(pl.Int32),
    )

odfs = []
for fpath in glob.glob("prior_deduplication_results/*"):
    odf = pl.read_csv(fpath)
    odf = odf.select(["crash_id", "DUPLICATE?"])
    odfs.append(odf)
odf = pl.concat(odfs).drop_nulls("crash_id")

df = df.join(odf, how="left", on="crash_id")

def get_candidate(df, col, tool="rand-preempt-sect_rw"):
    # Separate `loc` values for each tool
    loc_tool_a = df.filter(pl.col("tool") == tool)[col]
    loc_tool_b = df.filter(pl.col("tool") == "syzkaller")[col]

    # Find values in `loc_tool_a` not present in `loc_tool_b`
    unique_to_tool_a = loc_tool_a.filter(~loc_tool_a.is_in(loc_tool_b))

    # Filter original DataFrame for rows meeting the condition
    return df.filter(
        (pl.col("tool").is_in(["rand-preempt-sect_rw", "sect_rw", "sect_pct", "sect_pos"]) 
            & (pl.col(col).is_in(unique_to_tool_a))))



r = df.group_by(["tool", "cat", "trial"]).agg(pl.col("num_reports").sum())
r = r.group_by(["tool", "cat"]).agg(pl.col("num_reports").mean())

plt.figure(figsize=(12, 6))  # Adjust width and height
sns.barplot(data=r.to_pandas(), x="cat", y="num_reports", hue="tool")
plt.xticks(ha="right", rotation=45)
plt.savefig("report-cats.png", bbox_inches='tight')

r = df.group_by(["tool", "bug", "trial"]).agg(pl.col("num_reports").sum())
r = r.group_by(["tool", "bug"]).agg(pl.col("num_reports").mean())

plt.figure(figsize=(12, 6))  # Adjust width and height
sns.barplot(data=r.to_pandas(), x="bug", y="num_reports", hue="tool")
plt.xticks(ha="right", rotation=45)
plt.savefig("report-bugs.png", bbox_inches='tight')


r = df.group_by(["tool", "cat"]).agg(pl.col("crash_id").n_unique()).sort(by = ["tool", "cat"])
plt.figure(figsize=(12, 6))  # Adjust width and height
sns.barplot(data=r.to_pandas(), x="cat", y="crash_id", hue="tool")
plt.xticks(ha="right", rotation=45)
plt.savefig("unique-cats.png", bbox_inches='tight')


r.write_csv("unique-cats.csv")

r = df.group_by(["tool", "bug"]).agg(pl.col("crash_id").n_unique()).sort(by = ["tool", "bug"])

plt.figure(figsize=(12, 6))  # Adjust width and height
sns.barplot(data=r.to_pandas(), x="bug", y="crash_id", hue="tool")
plt.xticks(ha="right", rotation=45)
plt.savefig("unique-bugs.png", bbox_inches='tight')
print(matplotlib.get_backend())

r.write_csv("unique-bugs.csv")


# r = get_candidate(df.filter(pl.col("cat") == "KASAN"), "loc")
# r = get_candidate(df.filter(pl.col("cat") == "UBSAN"), "loc")
# r = get_candidate(df.filter(pl.col("cat") == "BUG"), "desc")
# r = get_candidate(df.filter(pl.col("cat") == "WARNING"), "loc")
# r = get_candidate(df.filter(pl.col("cat") == "OTHER"), "loc")

# r = get_candidate(df.filter(pl.col("cat") == "KASAN"), "loc")
# r = get_candidate(df.filter(pl.col("bug") == "possible_deadlock"), "loc")
r = df

r = r.filter(pl.col("exp").str.contains("18-MAR"))
r = r.filter(~pl.col("loc").str.contains("corrupted"))
r = r.filter(pl.col("min_asyncs_in_log") >= 2)
# r = r.filter(pl.col("max_programs_from_end_of_log_to_asyncs") > -6)
# r = r.filter(pl.col("num_reports") > 1)

r = r.filter(~pl.col("desc").str.contains("unable to handle kernel paging request"))
r = r.filter(~pl.col("desc").str.contains("rcu detected stall"))
r = r.filter(~pl.col("desc").str.contains("task hung"))
r = r.filter(pl.col("DUPLICATE?").is_null() | ((pl.col("DUPLICATE?") != "duplicate") & (pl.col("DUPLICATE?") != "yes" )))

r = r.unique("crash_id")
r.write_csv("goodq.csv")
print(r)
