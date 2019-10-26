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

export AFL_LLVM_CHECK_COLLISIONS=./.afl_check_coll.$$
rm -fv $AFL_LLVM_CHECK_COLLISIONS $AFL_LLVM_CHECK_COLLISIONS.lck $AFL_LLVM_CHECK_COLLISIONS.log

$* 2>&1 | tee $AFL_LLVM_CHECK_COLLISIONS.log

n=0
for i in `grep Instrumented $AFL_LLVM_CHECK_COLLISIONS.log | awk '{print$3}'`; do
  n=`expr $n + $i`
done
m=0
for i in `grep Instrumented $AFL_LLVM_CHECK_COLLISIONS.log | awk '{print$6}'`; do
  m=`expr $m + $i`
done
l=0
for i in `grep Instrumented $AFL_LLVM_CHECK_COLLISIONS.log | awk '{print$9}'`; do
  l=`expr $l + $i`
done

test -z "$AFL_DEBUG" && {
  rm -f $AFL_LLVM_CHECK_COLLISIONS $AFL_LLVM_CHECK_COLLISIONS.lck $AFL_LLVM_CHECK_COLLISIONS.log
} || ls -l $AFL_LLVM_CHECK_COLLISIONS $AFL_LLVM_CHECK_COLLISIONS.lck $AFL_LLVM_CHECK_COLLISIONS.log

echo
echo
echo afl++ llvm_mode count colliding edge coverage summary: $n locations, $m collisions, $l unknown
echo
