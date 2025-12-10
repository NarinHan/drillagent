# Records of Coverage Instrumentation Agent

Testing result: 24/29 projects successful.

## Successful instrumentation CVEs

exiv2_cve_2017_14864
faad2_CVE-2018-20198
gpac_cve-2023-5998
imagemagick_CVE-2019-13297
libarchive_CVE-2020-21674
libdwarf.cve-2022-32200
libheif-CVE-2023-49460
libiec61850-CVE-2021-45769
libjpeg-CVE-2020-13790
libplist.cve-2017-5545
libredwg.cve-2020-21816
libxls
matio-cve-2019-20018
md4c-2020-26148
njs_cve_2022_29779
openexr_cve_2020_16587
openjpeg_cve_2016_10507
readstat-cve-2018-5698
jq_CVE-2023-50246
upx_cve-2023-23457
wabt-cve-2022-43282
yara_cve-2017-5924
php_cve-2017-12933
yaml-cpp-cve-2018-20574

## Failed instrumentation CVEs

### mruby_cve-2018-14337
mruby's Rakefile is incompatible with the installed Ruby version (3.0) - The system installed Ruby 3.0.2, but mruby's old Rakefile (from 2018) was written for an older Ruby/Rake API that has since changed.

The error occurs at line 40 of mruby's Rakefile - This is a Ruby syntax/API compatibility issue in mruby's build system itself, unrelated to your coverage flags.

### qpdf

We are building a very old qpdf against a newer glibc toolchain.

```
/usr/bin/ld: qpdf/build/.libs/qpdf: hidden symbol `atexit' in /usr/lib/x86_64-linux-gnu/libc_nonshared.a(atexit.oS) is referenced by DSO
/usr/bin/ld: final link failed: bad value
clang-11: error: linker command failed with exit code 1
```

### libmodbus, libsndfile

The build commands from sec bench contain build system detection logic:

```bash
# 2. Handle different build systems
if [ -f "configure" ]; then
 echo "Found configure script, running with options: $CONFIG_OPTS"
 ./configure $CONFIG_OPTS
 echo "Building with make $MAKE_OPTS"
 make $MAKE_OPTS
elif [ -f "CMakeLists.txt" ]; then
 echo "Found CMakeLists.txt, using CMake build system"
 mkdir -p $BUILD_DIR
 cd $BUILD_DIR
 cmake $CMAKE_OPTS ..
 make $MAKE_OPTS
elif [ -f "Makefile" ] || [ -f "makefile" ]; then
 echo "Found Makefile, building with make $MAKE_OPTS"
 make $MAKE_OPTS
elif [ -f "meson.build" ]; then
 echo "Found meson.build, using Meson build system"
 mkdir -p $BUILD_DIR
 meson setup $BUILD_DIR .
 cd $BUILD_DIR
 ninja
elif [ -f "GNUmakefile" ]; then
 echo "Found GNUmakefile, building with make $MAKE_OPTS"
 make $MAKE_OPTS
elif [ -d ".git" ] && [ -f "Makefile.am" ]; then
 echo "Found Makefile.am, running autoreconf"
 autoreconf -i
 CC=clang CXX=clang++ CFLAGS="$COV_FLAGS $CFLAGS" CXXFLAGS="$COV_FLAGS $CXXFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS" ./configure $CONFIG_OPTS
 make $MAKE_OPTS
else
 echo "WARNING: No recognized build system found!"
 echo "Trying generic approach:"
 # Try to detect common source patterns and compile them
 if ls *.c >/dev/null 2>&1 || ls *.cpp >/dev/null 2>&1 || ls *.cc >/dev/null 2>&1; then
 echo "Found C/C++ source files, attempting direct compilation"
 if ls *.cpp >/dev/null 2>&1 || ls *.cc >/dev/null 2>&1; then
 CXX=${CXX:-g++}
 echo "Compiling C++ sources with $CXX"
 $CXX -g -O1 -fno-omit-frame-pointer -o main *.cpp *.cc 2>/dev/null || true
 elif ls *.c >/dev/null 2>&1; then
 CC=${CC:-gcc}
 echo "Compiling C sources with $CC"
 $CC -g -O1 -fno-omit-frame-pointer -o main *.c 2>/dev/null || true
 fi
 fi
fi
```

`CC=clang CXX=clang++ CFLAGS="$COV_FLAGS $CFLAGS" CXXFLAGS="$COV_FLAGS $CXXFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS"` is only set in branch `elif [ -d ".git" ] && [ -f "Makefile.am" ]`. SO, when the build system detection does not execute this branch, which instead goes to the first branch on our server, `$COV_FLAGS` will not be configured, and the build will succeed but the coverage instrumentation will fail.

## System Dependencies for building SEC-BENCH projects

For Debian / Ubuntu:

```bash
sudo apt-get update

# libsndfile
sudo apt install autogen

# libxls
sudo apt-get install -y gettext libtool autoconf automake autopoint autoconf-archive
```


## liblouis

The harness does not provide useful binary file:

```bash
\n\nrepro() {\n    echo \"REPRODUCING THE ISSUE FOR liblouis.cve-2023-26768...\"\n    
# TODO: Add commands to trigger the specific vulnerability\n    # For now, it's a placeholder.\n    
/testcase/driver-API-6223f21-lou_logFile-BO /testcase/poc-API-6223f21-lou_logFile-BO\n 
```