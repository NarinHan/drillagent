# DrillAgent


## About

**DrillAgent** aims to generate PoV test cases automatically for real-world CVE instances. Currently we only consider vulnerabilities in C/C++ open source repositories.

Target datasets:

- [SEC-bench](https://github.com/SEC-bench/SEC-bench)
- [PrimeVul](https://github.com/DLVulDet/PrimeVul)

## Getting Started

To test DrillAgent, just run:

```sh
python3 src/drillagent/scripts/main_test.py --test-loader datasets/sec-bench/CVE-instances --instances libplist.cve-2017-5545
# python3 tests/test_llm_complete_task.py
```

All the entry points should be included in `src/drillagent/scripts/`. You can also add your own python script here.

## Developing Tips

Each of us developers should create our own dev branch. After pushing some commits to our dev branch, we can create a pull request and merge it into the main branch.
