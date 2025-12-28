# DrillAgent


## About

**DrillAgent** aims to generate PoV test cases automatically for real-world CVE instances. Currently we only consider vulnerabilities in C/C++ open source repositories.

Target datasets:

- [SEC-bench](https://github.com/SEC-bench/SEC-bench)
- [Magma](https://github.com/HexHive/magma)
- [PrimeVul](https://github.com/DLVulDet/PrimeVul)

## Getting Started

To test DrillAgent on SEC-bench tasks, just run:

```sh
python3 src/drillagent/scripts/single_secb_task.py \
      --instance-id njs.cve-2022-27007 \
      --repo-path /home/shared_project/repos-llvm-cov/njs \
      --model-name gpt-5.1-2025-11-13

python3 src/drillagent/scripts/multiple_secb_task.py \
      --instance-ids njs.cve-2022-27007,mruby.cve-2022-0631,md4c.cve-2021-30027,jq.cve-2023-50246 \
      --repos-dir /home/shared_project/repos-llvm-cov \
      --model-name gpt-5.1-2025-11-13 \
      --disable-path-exploration --disable-crash-analysis
```

All the entry points should be included in `src/drillagent/scripts/`. You can also add your own python script here.

## Developing Tips

Each of us developers should create our own dev branch. After pushing some commits to our dev branch, we can create a pull request and merge it into the main branch.

Classes `DrillAgent`, `AgentConfig`, and most of agents should be benchmark-agnostic. Thus we can easily evaluate **DrillAgent** in different datasets.