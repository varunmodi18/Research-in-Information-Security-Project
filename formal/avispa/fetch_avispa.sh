#!/usr/bin/env bash
# Fetches the AVISPA tool chain used for formal/avispa/results/avispa/ (follow-up Part C1) into a
# directory OUTSIDE the repository, verifies every download against the SHA-256 recorded below, and
# prepares a private runtime so that no root access is needed. Nothing here is committed or installed
# system-wide. Usage:  formal/avispa/fetch_avispa.sh [TOOLS_DIR]   (default: ~/avispa_tools)
#
# What it fetches (all treated as untrusted input; each in its own directory):
#   SPAN 1.6 for Linux, 32-bit  -- the original AVISPA back-ends: OFMC "version of 2006/02/13",
#                                  CL-AtSe 2.2-5, hlpsl2if 2.0 (does not know the `hash_func` type)
#   SPAN 1.6 for Linux, 64-bit  -- its hlpsl2if (banner also "2.0") accepts `hash_func`, the dialect
#                                  RP9's Figs. 4-8 are written in; its CL-AtSe is 2.3-4. Its OFMC is a
#                                  later build (2012c) that is NOT used: see TOOLING.md (calibration).
#   Ubuntu packages, unpacked with dpkg-deb -x only (never installed):
#     libtinfo5, libffi6 (amd64)       -- old sonames the 64-bit binaries link against
#     libc6, libgmp10, libncurses5, libtinfo5 (i386) -- a private i386 runtime; the 32-bit binaries
#                                         are started through its loader: ld-linux.so.2 --library-path
set -euo pipefail
D="${1:-$HOME/avispa_tools}"
SPAN=https://people.irisa.fr/Thomas.Genet/span
UB=http://archive.ubuntu.com/ubuntu/pool
fetch() {  # dir url sha256
  mkdir -p "$D/$1"; local f="$D/$1/$(basename "$2")"
  [ -f "$f" ] || curl -sSL --retry 5 -C - -o "$f" "$2"
  echo "$3  $f" | sha256sum -c --quiet - || { echo "CHECKSUM MISMATCH: $f" >&2; exit 1; }
}
fetch dl_span16_linux32        $SPAN/span-1.6-linux.tar.gz                                   7b0a75a6564128ac8a6c92d11a7bfb5fe328f5640f3172c0fae68e0aaec8fb20
fetch dl_span16_linux64_ubuntu $SPAN/span-1.6-linux64-ubuntu.tar.gz                          6178c665898fce64e536838349caae4f7b510eeb2eb195a1dae7b2debe653211
fetch dl_libtinfo5             $UB/universe/n/ncurses/libtinfo5_6.3-2ubuntu0.3_amd64.deb     4df4288404108f1a156d014e8764a064e977e34e6d44931ab60451694c03c90d
fetch dl_libffi6               $UB/main/libf/libffi/libffi6_3.2.1-8_amd64.deb                fa26945b0aadfc72ec623c68be9cc59235a7fe42e2388f7015fd131f4fb06dc9
fetch dl_libc6_i386            $UB/main/g/glibc/libc6_2.39-0ubuntu8.9_i386.deb               5dd733076cd5490c912c663f1e844b1d0a214301d9515708c236e6fbeb38ff8e
fetch dl_libgmp10_i386         $UB/main/g/gmp/libgmp10_6.3.0+dfsg-3ubuntu1_i386.deb          8d206aa17f5d9ca1511392dcffd8a51a103f3cbfa9c9ac56a3cf5983d3e38802
fetch dl_ncurses5_i386         $UB/universe/n/ncurses/libncurses5_6.3-2ubuntu0.3_i386.deb    3ccbc52ca31acf0e8c915ec903c361f49b5a56ad8e81364f9483a8bda91dee7f
fetch dl_ncurses5_i386         $UB/universe/n/ncurses/libtinfo5_6.3-2ubuntu0.3_i386.deb      67b85304831409ba28dcdd415af8c0e849b8d0c1ef3d6427c3c81b978d1ee176

mkdir -p "$D/x_span16_linux32" "$D/x_span16_linux64" "$D/compat_lib" "$D/sysroot_i386"
tar -xzf "$D/dl_span16_linux32/span-1.6-linux.tar.gz" -C "$D/x_span16_linux32" --no-same-owner 2>/dev/null
tar -xzf "$D/dl_span16_linux64_ubuntu/span-1.6-linux64-ubuntu.tar.gz" -C "$D/x_span16_linux64" --no-same-owner 2>/dev/null
for p in dl_libtinfo5 dl_libffi6; do dpkg-deb -x "$D/$p"/*.deb "$D/$p/x"; done
cp -a "$D/dl_libtinfo5/x/lib/x86_64-linux-gnu/libtinfo.so.5"* "$D/dl_libffi6/x/usr/lib/x86_64-linux-gnu/libffi.so.6"* "$D/compat_lib/"
for d in "$D"/dl_libc6_i386/*.deb "$D"/dl_libgmp10_i386/*.deb "$D"/dl_ncurses5_i386/*.deb; do dpkg-deb -x "$d" "$D/sysroot_i386"; done
cp -a "$D/sysroot_i386/lib/i386-linux-gnu/"* "$D/sysroot_i386/usr/lib/i386-linux-gnu/"

# binaries actually used, with their checksums (verified, so a changed package is noticed)
sha256sum -c --quiet - <<EOF
b749ae6a78f2a82bfdff9d7f055df5b425e1f855aca0ff9c0476be2379076daf  $D/x_span16_linux32/span/bin/translator/hlpsl2if
58c2e4d76654e26c86d6e9aca25a1522098bc898a96abf6af1efed136dc8c5dd  $D/x_span16_linux32/span/bin/backends/ofmc/ofmc
25e206968892a5a5271f88d8ada8f28addabfc8a6057cc459f011c0bcc5670be  $D/x_span16_linux32/span/bin/backends/cl/cl-atse
b9c360a2972fe24a79dc1dda271efb20caa2a00e7a8cd196e4ca00e83be0f5e6  $D/x_span16_linux64/span/bin/translator/hlpsl2if
3a6fa017a212a74c2d38f26b17d411bc3313107334fe2158306a551f61049f27  $D/x_span16_linux64/span/bin/backends/cl/cl-atse
1ccaa18eb8ec08c8ae422e34ddacebd017758d112c106758f206bb063a16eb45  $D/x_span16_linux64/span/bin/backends/ofmc/ofmc
EOF
echo "AVISPA tool chain ready in $D. Run:  AVISPA_TOOLS=$D formal/avispa/run_avispa.sh"
