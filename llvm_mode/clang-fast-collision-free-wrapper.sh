#!/bin/sh

test -z "$1" -o "$1" = "-h" -o "$1" = "--help" && {
  echo Syntax: $0 build-command
  echo
  echo Builds the target with mostly collision free edge coverage
  echo Warning: do not build the target with multiple threads, e.g. -j4
  echo
  exit 1
}

test "$1" = "DEBUG" && { export AFL_DEBUG=1 ; shift ; }

test -z "$CC" && export CC=afl-clang-fast
test -z "$CXX" && export CXX=afl-clang-fast++
export AFL_LLVM_NON_COLLIDING_COVERAGE=./.afl_nocoll_cov.$$
rm -fv $AFL_LLVM_NON_COLLIDING_COVERAGE $AFL_LLVM_NON_COLLIDING_COVERAGE.lck $AFL_LLVM_NON_COLLIDING_COVERAGE.log

$* 2>&1 | tee $AFL_LLVM_NON_COLLIDING_COVERAGE.log

n=0
for i in `grep Instrumented $AFL_LLVM_NON_COLLIDING_COVERAGE.log | awk '{print$3}'`; do
  n=`expr $n + $i`
done
m=0
for i in `grep Instrumented $AFL_LLVM_NON_COLLIDING_COVERAGE.log | awk '{print$6}'`; do
  m=`expr $m + $i`
done

test -z "$AFL_DEBUG" && {
  rm -f $AFL_LLVM_NON_COLLIDING_COVERAGE $AFL_LLVM_NON_COLLIDING_COVERAGE.lck $AFL_LLVM_NON_COLLIDING_COVERAGE.log
} || ls -l $AFL_LLVM_NON_COLLIDING_COVERAGE $AFL_LLVM_NON_COLLIDING_COVERAGE.lck $AFL_LLVM_NON_COLLIDING_COVERAGE.log

echo
echo
echo afl++ llvm_mode non-colliding-coverage summary: $n locations, $m collisions
echo
