#include <unordered_set>
#include <stack>
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/Transforms/Utils/Local.h"

using namespace llvm;

#define DEBUG_TYPE "inject-sched-point"

static cl::opt<bool> ClDumpIRs(
	"dump-ir",
	cl::desc("Dump IRs before and after instrumenting callbacks (for debugging)"),
	cl::init(false));

STATISTIC(NumInstrumentedSchedPoints, "Number of instrumented scheduling points");

struct MemInstr
{
public:
	bool instrumentFunction(Function &F, const TargetLibraryInfo &TLI);

private:
	bool instrumentAll(Function &F, const TargetLibraryInfo &TLI);
	bool isInterestingLoadStore(Instruction *I);
	void chooseInstructionsToInstrument(
		SmallVectorImpl<Instruction *> &Local, SmallVectorImpl<Instruction *> &All,
		const DataLayout &DL);
	bool addrPointsToConstantData(Value *Addr);
	bool instrumentLoadOrStore(Instruction *I, const DataLayout &DL);
	int getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL);

	SmallVector<Instruction *, 8> AllLoadsAndStores;
	SmallVector<Instruction *, 8> LocalLoadsAndStores;
	// Accesses sizes are powers of two: 1, 2, 4, 8, 16.
	static const size_t kNumberOfAccessSizes = 5;
};

static void dumpIR(Function &F, std::string prefix)
{
	const char *tmpdirp;
	std::string tmpdir;
	if ((tmpdirp = std::getenv("TMP_DIR")))
		tmpdir.append(tmpdirp);

	std::string fn = tmpdir + "/" + F.getName().str() + "." + prefix + ".ll";
	std::error_code EC;

	raw_fd_ostream out(fn, EC, sys::fs::OF_Text);

	F.print(out, NULL /*default*/, false /*default*/, true /*IsForDebug*/);
}

// Do not instrument known races/"benign races" that come from compiler
// instrumentatin. The user has no way of suppressing them.
static bool shouldInstrumentReadWriteFromAddress(const Module *M, Value *Addr)
{
	// Peel off GEPs and BitCasts.
	Addr = Addr->stripInBoundsOffsets();

	if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Addr))
	{
		if (GV->hasSection())
		{
			StringRef SectionName = GV->getSection();
			// Check if the global is in the PGO counters section.
			auto OF = Triple(M->getTargetTriple()).getObjectFormat();
			if (SectionName.endswith(
					getInstrProfSectionName(IPSK_cnts, OF, /*AddSegmentInfo=*/false)))
				return false;
		}

		// Check if the global is private gcov data.
		if (GV->getName().startswith("__llvm_gcov") ||
			GV->getName().startswith("__llvm_gcda"))
			return false;
	}

	// Do not instrument acesses from different address spaces; we cannot deal
	// with them.
	if (Addr)
	{
		Type *PtrTy = cast<PointerType>(Addr->getType()->getScalarType());
		if (PtrTy->getPointerAddressSpace() != 0)
			return false;
	}

	return true;
}

static bool isBUG_X86_64(Instruction *I)
{
	if (CallInst *CI = dyn_cast<CallInst>(I))
	{
		if (CI->isInlineAsm())
		{
			auto *Asm = cast<InlineAsm>(CI->getCalledOperand());
			auto Str = Asm->getAsmString();
#define UD2 ".byte 0x0f, 0x0"
			return Str.find(UD2) != std::string::npos;
		}
	}
	return false;
}

bool MemInstr::isInterestingLoadStore(Instruction *I)
{
	if (auto *LI = dyn_cast<LoadInst>(I))
		return !LI->isAtomic() && LI->getSyncScopeID() != SyncScope::SingleThread;
	else if (auto *SI = dyn_cast<StoreInst>(I))
		return !SI->isAtomic() && SI->getSyncScopeID() != SyncScope::SingleThread;
	else
		return false;
}

void MemInstr::chooseInstructionsToInstrument(
	SmallVectorImpl<Instruction *> &Local,
	SmallVectorImpl<Instruction *> &All,
	const DataLayout &DL)
{
	SmallPtrSet<Value *, 8> WriteTargets;
	// Iterate from the end.
	for (Instruction *I : reverse(Local))
	{
		if (StoreInst *Store = dyn_cast<StoreInst>(I))
		{
			Value *Addr = Store->getPointerOperand();
			if (!shouldInstrumentReadWriteFromAddress(I->getModule(), Addr))
				continue;
			WriteTargets.insert(Addr);
		}
		else
		{
			LoadInst *Load = cast<LoadInst>(I);
			Value *Addr = Load->getPointerOperand();
			if (!shouldInstrumentReadWriteFromAddress(I->getModule(), Addr))
				continue;
			if (addrPointsToConstantData(Addr))
				// Addr points to some constant data -- it can not race with any
				// writes.
				continue;
		}
		Value *Addr = isa<StoreInst>(*I) ? cast<StoreInst>(I)->getPointerOperand()
										 : cast<LoadInst>(I)->getPointerOperand();
		if (isa<AllocaInst>(getUnderlyingObject(Addr)) &&
			!PointerMayBeCaptured(Addr, true, true))
		{
			// The variable is addressable but not captured, so it cannot be
			// referenced from a different thread and participate in a data race
			// (see llvm/Analysis/CaptureTracking.h for details).
			continue;
		}
		All.push_back(I);
	}
	Local.clear();
}

bool MemInstr::addrPointsToConstantData(Value *Addr)
{
	// If this is a GEP, just analyze its pointer operand.
	if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(Addr))
		Addr = GEP->getPointerOperand();

	if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Addr))
	{
		if (GV->isConstant())
		{
			// Reads from constant globals can not race with any writes.
			return true;
		}
	}
	return false;
}

// int MemInstr::getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL)
// {
// 	Type *OrigPtrTy = Addr->getType();

// 	// Check if the pointer is opaque; if so, return -1 or handle appropriately.
// 	if (!OrigPtrTy->isPointerTy() || cast<PointerType>(OrigPtrTy)->isOpaque())
// 		// Handle the opaque pointer case (e.g., skip or return -1).
// 		dbgs() << "isOpaque\n";
// 		return -1;

// 	Type *OrigTy = cast<PointerType>(OrigPtrTy)->getNonOpaquePointerElementType();

// 	assert(OrigTy->isSized());
// 	uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
// 	if (TypeSize != 8 && TypeSize != 16 && TypeSize != 32 && TypeSize != 64)
// 	{
// 		// Ignore all unusual sizes.
// 		return -1;
// 	}
// 	size_t Idx = countTrailingZeros(TypeSize / 8);
// 	assert(Idx < kNumberOfAccessSizes);
// 	return Idx;
// }

bool MemInstr::instrumentLoadOrStore(Instruction *I, const DataLayout &DL)
{
	auto Loc = I->getDebugLoc();
	Module &M = *I->getParent()->getParent()->getParent();
	auto &Ctx = M.getContext();

	// STEP 1: Inject the declaration of printf
	FunctionType *YieldTy = FunctionType::get(
		IntegerType::getInt32Ty(Ctx),
		{PointerType::getUnqual(IntegerType::getInt8Ty(Ctx)), // Parameter `void*addr`
		IntegerType::getInt1Ty(Ctx)},						  // Parameter `bool isWrite`
		false);

	FunctionCallee Yield = M.getOrInsertFunction("check_preempt_and_yield", YieldTy);

	Function *YieldF = dyn_cast<Function>(Yield.getCallee());
	YieldF->setDoesNotThrow();

	bool IsWrite = isa<StoreInst>(*I);
	Value *Addr = IsWrite ? cast<StoreInst>(I)->getPointerOperand()
						  : cast<LoadInst>(I)->getPointerOperand();

	if (Addr->isSwiftError())
	{
		dbgs() << "isSwiftError\n";
		return false;
	}
	// int Idx = getMemoryAccessFuncIndex(Addr, DL);
	// if (Idx < 0){
	// 	dbgs() << "idx < 0\n";
	// 	return false;
	// }

	// dbgs() << " Injecting call to yield inside " << I->getParent()->getName() << " function\n";

	ConstantInt *IsWriteVal = ConstantInt::get(IntegerType::getInt1Ty(Ctx), IsWrite);

	// auto NI = I->getNextNonDebugInstruction();
	// IRBuilder<> Builder(NI);
	IRBuilder<> Builder(I);
	Value *AddrPtr = Builder.CreatePointerCast(Addr, IRBuilder<>(Ctx).getInt8PtrTy());
	auto CI = Builder.CreateCall(Yield, {AddrPtr, IsWriteVal});
	CI->setDebugLoc(Loc);

	NumInstrumentedSchedPoints++;

	return true;
}

bool MemInstr::instrumentAll(Function &F, const TargetLibraryInfo &TLI)
{
	if (F.getSection() == ".noinstr.text")
		return false;

	bool Res = false;
	bool HasCall = false;
	const DataLayout &DL = F.getParent()->getDataLayout();

	for (auto &BB : F)
	{
		for (auto &Inst : BB)
		{
			if (isInterestingLoadStore(&Inst))
				LocalLoadsAndStores.push_back(&Inst);
			else if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst))
			{
				if (CallInst *CI = dyn_cast<CallInst>(&Inst))
					maybeMarkSanitizerLibraryCallNoBuiltin(CI, &TLI);

				HasCall = true;
				chooseInstructionsToInstrument(LocalLoadsAndStores, AllLoadsAndStores, DL);
				if (isBUG_X86_64(&Inst))
					break;
			}
		}
		chooseInstructionsToInstrument(LocalLoadsAndStores, AllLoadsAndStores, DL);
	}

	// LLVM_DEBUG(dbgs() << "=== Instrumenting a function " << F.getName() << " ===\n");

	int NumInjected = 0;
	for (auto Inst : AllLoadsAndStores)
	{
		Res |= instrumentLoadOrStore(Inst, DL);
		NumInjected += Res;
	}
	dbgs() << "=== Instrumenting a function " << F.getName() << " ===\n";
	dbgs() << "size of collected Load or Store inst: " << NumInjected << "\n";

	return Res | HasCall;
}

bool MemInstr::instrumentFunction(Function &F, const TargetLibraryInfo &TLI)
{
	// initialize(*F.getParent());
	return instrumentAll(F, TLI);
}

struct InjectSchedPoint : public PassInfoMixin<InjectSchedPoint>
{
public:
	PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};

PreservedAnalyses InjectSchedPoint::run(Function &F,
										FunctionAnalysisManager &AM)
{
	MemInstr MemInstr;

	auto &TLI = AM.getResult<TargetLibraryAnalysis>(F);
	if (ClDumpIRs)
		dumpIR(F, std::string("before"));

	bool Changed = MemInstr.instrumentFunction(F, TLI);

	if (ClDumpIRs)
		dumpIR(F, std::string("after"));

	return (Changed ? PreservedAnalyses::none()
					: PreservedAnalyses::all());
}

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------

// // Used for Opt
// PassPluginLibraryInfo getPassPluginInfo()
// {
// 	return {LLVM_PLUGIN_API_VERSION, "inject-sched-point", LLVM_VERSION_STRING,
// 			[](PassBuilder &PB)
// 			{
// 				PB.registerPipelineParsingCallback(
// 					[](StringRef Name, FunctionPassManager &FPM,
// 					   ArrayRef<PassBuilder::PipelineElement>)
// 					{
// 						if (Name == "inject-sched-point")
// 						{
// 							FPM.addPass(InjectSchedPoint());
// 							return true;
// 						}
// 						return false;
// 					});
// 			}};
// }

// Used for clang pipeline
PassPluginLibraryInfo getPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "inject-sched-point", LLVM_VERSION_STRING,
			[](PassBuilder &PB)
			{
				PB.registerPipelineEarlySimplificationEPCallback(
					[&](ModulePassManager &MPM, auto)
					{
						MPM.addPass(createModuleToFunctionPassAdaptor(InjectSchedPoint()));
						return true;
					});
			}};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo()
{
	return getPassPluginInfo();
}
