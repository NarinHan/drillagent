# DrillAgent Tests

This directory contains test scripts for DrillAgent components.

## test_secb_batch_parsing.py

Batch test script for validating vulnerability location and harness command extraction from SEC-bench CVE instances.

### Features

- Processes all 200 CVE instances from SEC-bench dataset
- Extracts and validates vulnerability locations from sanitizer reports
- Extracts and validates harness commands from repro() functions
- Provides detailed statistics and results

### Usage

**Basic usage** (summary statistics only):
```bash
python3 tests/test_secb_batch_parsing.py
```

**Verbose mode** (detailed results for each CVE):
```bash
python3 tests/test_secb_batch_parsing.py --verbose
```

**Save results to file**:
```bash
python3 tests/test_secb_batch_parsing.py --output tests/results.txt
```

**Process limited number of CVEs**:
```bash
python3 tests/test_secb_batch_parsing.py --max-count 50
```

**Custom dataset path**:
```bash
python3 tests/test_secb_batch_parsing.py --dataset-path /path/to/CVE-instances
```

### Test Results

Current performance on 200 CVE instances:

- **Total instances loaded**: 200/200 (100%)
- **Vulnerability location extraction**: 187/200 (93.5%)
- **Harness command extraction**: 199/200 (99.5%)
- **Both successfully extracted**: 186/200 (93.0%)

### Output Format

The script provides:

1. **Summary Statistics**
   - Total CVEs processed
   - Success rates for location and command extraction

2. **Missing Data Examples**
   - Lists CVEs missing vulnerability location
   - Lists CVEs missing harness command

3. **Detailed Results** (with `--verbose`)
   - Per-CVE extraction results
   - Actual extracted values

### Exit Codes

- `0`: Success (>= 80% success rate)
- `1`: Warning (< 80% success rate)

### Examples

**Check overall success rate**:
```bash
python3 tests/test_secb_batch_parsing.py
```

**Generate detailed report**:
```bash
python3 tests/test_secb_batch_parsing.py --verbose --output reports/detailed_results.txt
```

**Quick test on subset**:
```bash
python3 tests/test_secb_batch_parsing.py --max-count 10 --verbose
```

## Files

- `test_secb_batch_parsing.py` - Main batch parsing test script
- `batch_parsing_results.txt` - Latest test results (generated)
- `README.md` - This file
