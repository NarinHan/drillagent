## SEC-bench dataset


This benchmark contains 200 real-world CVE instances in C/C++ repos. 

There are 200 json files in `./CVE-instances/` dir. The following fields in each json file will be used as DrillAgent's input:

- instance_id (and other basic info)
- base_commit
- build_sh
- secb_sh
- sanitizer_report

