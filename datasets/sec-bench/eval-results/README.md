# Evaluation Results

This folder holds the task-ID subsets and result sets behind the experiments
reported in our paper ([arXiv](https://arxiv.org/pdf/2602.13574)).

Every file is a plain newline-separated list of [SEC-bench](https://github.com/SEC-bench/SEC-bench)
task IDs in the form `<project>.<cve-id>`. `drillagent_crash_set.txt` additionally
groups its entries under `#`-prefixed section headers.

| File | # tasks | What it is |
|------|:------:|------------|
| `drillagent_crash_set.txt`          | 67 | All tasks where DrillAgent triggered a crash, grouped into **Direct Success** (54), **Indirect Success** (1), and **New Find** (12) — the *New Find* group are variant crashes whose location/path differs from the labeled CVE. |
| `drillagent_validated_pov_set.txt`  | 55 | Tasks for which DrillAgent produced a sanitizer-validated PoV. |
| `unique_validated_pov_set.txt`      | 29 | Tasks solved **only by DrillAgent** — cases where no compared baseline produced a valid PoV. |
| `drillagent_variant_pov_set.txt`    | 12 | Tasks where DrillAgent generated a **variant PoV**: it triggers a crash, but the crash location / path may differ from the labeled vulnerability. |
| `ablation_subset.txt`               | 30 | Task subset used for the ablation studies. |
| `oh-subset.txt`                     | 60 | Test set for the **OpenHands** baseline. |
| `history-succeed-subset.txt`        | 47 | Tasks that **other (prior) agents** have historically succeeded on. |
| `random_top_70.txt`                 | 70 | Randomly sampled 70-task subset. |

> These lists are frozen snapshots matching the paper. For the actively
> developed code, see the [`main-dev`](https://github.com/learjet5/DrillAgent/tree/main-dev) branch.
