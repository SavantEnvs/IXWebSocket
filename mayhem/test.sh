#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's unit tests (built by mayhem/build.sh in build/tests), run through ctest: the Catch2
# programs plus IXWsProxyTest (a Python unittest driving the ws CLI against a local SOCKS5 peer). They
# assert parsed values, round-trip results and protocol behaviour over loopback sockets (IXDNSLookupTest
# only resolves literals, localhost and a reserved .invalid name, so it needs no network). Excluded:
# IXWebSocketBuildSettings (re-configures CMake, a build-system check, not a library test).
TESTDIR="$SRC/build/tests"
if [ ! -f "$TESTDIR/CTestTestfile.cmake" ]; then
  echo "test.sh: $TESTDIR is not built — mayhem/build.sh must build the test suite" >&2
  emit_ctrf "cmake-ctest" 0 1 0
  exit 1
fi
# Each test runs through ctest (which sets its working directory), and passes only if ctest passes
# it AND its Catch2 output carries the "All tests passed (N assertions in M test cases)" summary (or,
# when some cases are skipped, "assertions: N | N passed" with N > 0), so
# a binary that exits 0 without running its assertions counts as failed. IXWsProxyTest is a Python
# unittest, so it instead needs unittest's "Ran N tests" (N > 0) followed by a line that is exactly
# "OK" or "OK (skipped=K)" with K < N (ctest -V prefixes each output line with "<test number>: "; the
# one skip is upstream's Apple-only Network.framework case).
names="$(cd "$TESTDIR" && ctest -N -E '^IXWebSocketBuildSettings$' | sed -nE 's/^ *Test +#[0-9]+: +([^ ]+).*/\1/p')"
if [ -z "$names" ]; then
  echo "test.sh: ctest lists no tests in $TESTDIR" >&2
  emit_ctrf "cmake-ctest" 0 1 0
  exit 1
fi
passed=0; failed=0
for name in $names; do
  out="$(cd "$TESTDIR" && ctest -V --timeout 120 -R "^${name}\$" 2>&1)"
  rc=$?
  if [ "$name" = IXWsProxyTest ]; then
    summary_ok() {
      local ran ok skipped
      ran="$(sed -nE 's/^([0-9]+: )?Ran ([1-9][0-9]*) tests? in .*/\2/p' <<<"$out" | tail -1)"
      ok="$(grep -A3 -E '^([0-9]+: )?Ran [1-9][0-9]* tests? in ' <<<"$out" | grep -xE '([0-9]+: )?OK( \(skipped=[0-9]+\))?' | tail -1)"
      [ -n "$ran" ] && [ -n "$ok" ] || return 1
      skipped="$(sed -nE 's/.*skipped=([0-9]+).*/\1/p' <<<"$ok")"
      [ "${skipped:-0}" -lt "$ran" ]
    }
  else
    summary_ok() { grep -qE 'All tests passed \([1-9][0-9]* assertions? in [1-9][0-9]* test cases?\)|assertions: +([1-9][0-9]*) \| +\1 passed$' <<<"$out"; }
  fi
  if [ $rc -eq 0 ] && summary_ok; then
    passed=$((passed + 1)); echo "PASS $name"
  else
    failed=$((failed + 1)); echo "FAIL $name"; printf '%s\n' "$out" | tail -40
  fi
done
emit_ctrf "cmake-ctest" "$passed" "$failed" 0
