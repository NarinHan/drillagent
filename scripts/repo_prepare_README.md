# Quick Start Guide: repo_prepare.sh

## Overview

The `repo_prepare.sh` script automates the initialization of all 29 GitHub repositories from the SEC-bench CVE instances dataset.

## Basic Usage

### 1. Clone all repositories (default location)

```bash
cd path/to/DrillAgent
./scripts/repo_prepare.sh
```

This will clone all 29 repositories to `DrillAgent/repos/`

### 2. Clone to a specific location

```bash
./scripts/repo_prepare.sh --dest /path/to/your/repos
```

### 3. Use more parallel jobs (faster on good connections)

```bash
./scripts/repo_prepare.sh --jobs 8
```

### 4. Force re-clone existing repositories

```bash
./scripts/repo_prepare.sh --force
```

## Repository List

The script clones these 29 projects:

| # | Project | Repository URL | CVE Count |
|---|---------|---------------|-----------|
| 1 | exiv2 | https://github.com/exiv2/exiv2 | 10 | 
| 2 | faad2 | https://github.com/knik0/faad2 | 12 |
| 3 | gpac | https://github.com/gpac/gpac | 43 |
| 4 | imagemagick | https://github.com/imagemagick/imagemagick | 33 |
| 5 | jq | https://github.com/jqlang/jq | 1 |
| 6 | libarchive | https://github.com/libarchive/libarchive | 3 |
| 7 | libdwarf-code | https://github.com/davea42/libdwarf-code | 2 |
| 8 | libredwg | https://github.com/libredwg/libredwg | 22 |
| 9 | matio | https://github.com/tbeu/matio | 7 |
| 10 | md4c | https://github.com/mity/md4c | 3 |
| 11 | mruby | https://github.com/mruby/mruby | 21 |
| 12 | njs | https://github.com/nginx/njs | 17 |
| 13 | php-src | https://github.com/php/php-src | 2 |
| 14 | yaml-cpp | https://github.com/jbeder/yaml-cpp | 1 |
| 15 | openexr | https://github.com/academysoftwarefoundation/openexr | 3 |
| 16 | openjpeg | https://github.com/uclouvain/openjpeg | 5 |
| 17 | libheif | https://github.com/strukturag/libheif | 2 |
| 18 | libiec61850 | https://github.com/mz-automation/libiec61850 | 2 |
| 19 | libjpeg-turbo | https://github.com/libjpeg-turbo/libjpeg-turbo | 1 |
| 20 | liblouis | https://github.com/liblouis/liblouis | 1 |
| 21 | libmodbus | https://github.com/stephane/libmodbus | 1 |
| 22 | libplist | https://github.com/libimobiledevice/libplist | 1 |
| 23 | libsndfile | https://github.com/libsndfile/libsndfile | 1 |
| 24 | libxls | https://github.com/libxls/libxls | 1 |
| 25 | qpdf | https://github.com/qpdf/qpdf | 1 |
| 26 | upx | https://github.com/upx/upx | 3 |
| 27 | yara | https://github.com/virustotal/yara | 3 |
| 28 | wabt | https://github.com/webassembly/wabt | 1 |
| 29 | readstat | https://github.com/wizardmac/readstat | 1 |

**Total:** 29 projects, 200 CVE instances
