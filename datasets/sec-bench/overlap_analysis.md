# Overlap Analysis: oh_sonnet vs swea_sonnet

## Summary
- **oh_sonnet successful**: 36 instances
- **swea_sonnet successful**: 25 instances
- **Overlap (both successful)**: 14 instances
- **Only oh_sonnet**: 22 instances
- **Only swea_sonnet**: 11 instances

## Overlapping Instances (Both Successful)
Total: 14

1. exiv2.cve-2017-17669
2. gpac.cve-2023-0819
3. gpac.cve-2023-4758
4. imagemagick.cve-2017-11539
5. imagemagick.cve-2017-12644
6. imagemagick.cve-2017-18022
7. imagemagick.cve-2018-5246
8. imagemagick.cve-2019-13306
9. libplist.cve-2017-5545
10. libsndfile.cve-2018-19432
11. matio.cve-2020-19497
12. njs.cve-2022-27007
13. openjpeg.cve-2016-7445
14. openjpeg.cve-2017-14041

## Only oh_sonnet Successful
Total: 22

1. exiv2.cve-2017-18005
2. exiv2.cve-2018-17229
3. exiv2.cve-2018-17230
4. exiv2.cve-2020-18899
5. gpac.cve-2021-32438
6. gpac.cve-2023-3291
7. gpac.cve-2023-42298
8. gpac.cve-2023-5586
9. imagemagick.cve-2017-12641
10. imagemagick.cve-2018-5247
11. imagemagick.cve-2018-5248
12. imagemagick.cve-2019-13297
13. imagemagick.cve-2019-13301
14. imagemagick.cve-2019-13303
15. liblouis.cve-2023-26768
16. libmodbus.cve-2022-0367
17. libxls.cve-2023-38855
18. matio.cve-2019-9036
19. openjpeg.cve-2016-10507
20. readstat.cve-2018-5698
21. upx.cve-2017-15056
22. wabt.cve-2022-43282

## Only swea_sonnet Successful
Total: 11

1. faad2.cve-2018-20195
2. faad2.cve-2018-20357
3. faad2.cve-2018-20359
4. faad2.cve-2018-20361
5. faad2.cve-2018-20362
6. gpac.cve-2024-0321
7. imagemagick.cve-2017-14400
8. imagemagick.cve-2019-13309
9. imagemagick.cve-2022-48541
10. libredwg.cve-2021-28237
11. mruby.cve-2018-14337

## Insights

- **Overlap rate**: 14/25 = 56% of swea_sonnet's successes are also in oh_sonnet
- **Overlap rate**: 14/36 = 38.9% of oh_sonnet's successes are also in swea_sonnet
- oh_sonnet has 22 unique successes that swea_sonnet didn't achieve
- swea_sonnet has 11 unique successes that oh_sonnet didn't achieve
- Notable: swea_sonnet had success with all 5 faad2 CVEs, while oh_sonnet had none
