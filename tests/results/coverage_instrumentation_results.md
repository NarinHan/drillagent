# Records of Coverage Instrumentation Agent

## Successful instrumentation CVEs

exiv2_cve_2017_14864
faad2_CVE-2018-20198
imagemagick_CVE-2019-13297
libarchive_CVE-2020-21674
njs_cve_2022_29779
njs_cve_2022_29780
openexr_cve_2020_16587
openjpeg_cve_2016_10507
jq_CVE-2023-50246
upx_cve-2023-23457

## Failed instrumentation CVEs

### mruby_cve-2018-14337
mruby's Rakefile is incompatible with the installed Ruby version (3.0) - The system installed Ruby 3.0.2, but mruby's old Rakefile (from 2018) was written for an older Ruby/Rake API that has since changed.

The error occurs at line 40 of mruby's Rakefile - This is a Ruby syntax/API compatibility issue in mruby's build system itself, unrelated to your coverage flags.