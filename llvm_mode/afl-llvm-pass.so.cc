/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CFG.h"

using namespace llvm;

namespace {

class AFLCoverage : public ModulePass {

 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {

    char *instWhiteListFilename = getenv("AFL_LLVM_WHITELIST");
    if (instWhiteListFilename) {

      std::string   line;
      std::ifstream fileStream;
      fileStream.open(instWhiteListFilename);
      if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_WHITELIST");
      getline(fileStream, line);
      while (fileStream) {

        myWhitelist.push_back(line);
        getline(fileStream, line);

      }

    }

  }

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {

  //  return "American Fuzzy Lop Instrumentation";
  // }

 protected:
  std::list<std::string> myWhitelist;

};

}  // namespace

char AFLCoverage::ID = 0;

bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

  struct timeval  tv;
  struct timezone tz;
  u32             rand_seed;

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST " by <lszekeres@google.com>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (!myWhitelist.empty()) {

        bool instrumentBlock = false;

        /* Get the current location using debug information.
         * For now, just instrument the block if we are not able
         * to determine our location. */
        DebugLoc Loc = IP->getDebugLoc();
        if (Loc) {

          DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

          unsigned int instLine = cDILoc->getLine();
          StringRef    instFilename = cDILoc->getFilename();

          if (instFilename.str().empty()) {

            /* If the original location is empty, try using the inlined location
             */
            DILocation *oDILoc = cDILoc->getInlinedAt();
            if (oDILoc) {

              instFilename = oDILoc->getFilename();
              instLine = oDILoc->getLine();

            }

          }

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

        /* Either we couldn't figure out our location or the location is
         * not whitelisted, so we skip instrumentation. */
        if (!instrumentBlock) continue;

      }

      if (AFL_R(100) >= inst_ratio) continue;

/* There is a problem with Ubuntu 18.04 and llvm 6.0 (see issue #63).
   The inline function successors() is not inlined and also not found at runtime
   :-( As I am unable to detect Ubuntu18.04 heree, the next best thing is to
   disable this optional optimization for LLVM 6.0.0 and Linux */
#if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
      // only instrument if this basic block is the destination of a previous
      // basic block that has multiple successors
      // this gets rid of ~5-10% of instrumentations that are unnecessary
      // result: a little more speed and less map pollution
      int more_than_one = -1;
      // fprintf(stderr, "BB %u: ", cur_loc);
      for (BasicBlock *Pred : predecessors(&BB)) {

        int count = 0;
        if (more_than_one == -1) more_than_one = 0;
        // fprintf(stderr, " %p=>", Pred);

        for (BasicBlock *Succ : successors(Pred)) {

          // if (count > 0)
          //  fprintf(stderr, "|");
          if (Succ != NULL) count++;
          // fprintf(stderr, "%p", Succ);

        }

        if (count > 1) more_than_one = 1;

      }

      // fprintf(stderr, " == %d\n", more_than_one);
      if (more_than_one != 1) continue;
#endif

/* Define only one of these three! 1 is the fastest, 3 is the slowest */
#define VARIANT_1 1	/* ADD variant, fast and good */
// #define VARIANT_2 1  /* XOR + << 1 variant - slower and really bad */
// #define VARIANT_3 1  /* both */

     /* Get map pointer */
      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

#if VARIANT_1 || VARIANT_3
      /* Counter = map[0] */
      Value *   MapPtrPtr = IRB.CreateGEP(MapPtr, ConstantInt::get(Int64Ty, 0));
      LoadInst *Counter = IRB.CreateLoad(Int64Ty, MapPtrPtr);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Counter += IP */

      Value *Rip = BlockAddress::get(&F, &BB);
      Value *Added = IRB.CreateAdd(Rip, Counter);
      
      /* map[0] = Added */

      IRB.CreateStore(Added, MapPtrPtr)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
#endif

#ifdef VARIANT_3
      /* Counter2 = map[1] */
      Value *   MapPtrPtr2 = IRB.CreateGEP(MapPtr, ConstantInt::get(Int64Ty, 1));
      LoadInst *Counter2 = IRB.CreateLoad(Int64Ty, MapPtrPtr2);
      Counter2->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* (Counter2 ^ IP) << 1 */

      Value *Xored = IRB.CreateXor(Rip, Counter2);
      Value *Shifted = IRB.CreateShl(Xored, 1);

      /* map[1] = Shifted */

      IRB.CreateStore(Shifted, MapPtrPtr2)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
#endif

#ifdef VARIANT_2
      /* Counter2 = map[0] */
      Value *   MapPtrPtr2 = IRB.CreateGEP(MapPtr, ConstantInt::get(Int64Ty, 0));
      LoadInst *Counter2 = IRB.CreateLoad(Int64Ty, MapPtrPtr2);
      Counter2->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* (Counter2 ^ IP) << 1 */

      Value *Rip = BlockAddress::get(&F, &BB);
      Value *Xored = IRB.CreateXor(Rip, Counter2);
      Value *Shifted = IRB.CreateShl(Xored, 1);

      /* map[1] = Shifted */

      IRB.CreateStore(Shifted, MapPtrPtr2)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
#endif

      inst_blocks++;

    }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio);

  }

  return true;

}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

