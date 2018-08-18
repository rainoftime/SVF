/*
 // On Demand Value Flow Analysis
 //
 // Author: Yulei Sui,
 */

//#include "AliasUtil/AliasAnalysisCounter.h"
//#include "MemoryModel/ComTypeModel.h"
#include "DDA/DDAPass.h"

//#include <llvm-c/Core.h> // for LLVMGetGlobalContext()
#include <llvm/Support/CommandLine.h>	// for cl
#include <llvm/Support/FileSystem.h>	// for sys::fs::F_None
#include <llvm/Bitcode/BitcodeWriterPass.h>  // for bitcode write
#include <llvm/IR/LegacyPassManager.h>		// pass manager
#include <llvm/Support/Signals.h>	// singal for command line
#include <llvm/IRReader/IRReader.h>	// IR reader for bit file
#include <llvm/Support/ToolOutputFile.h> // for tool output file
#include <llvm/Support/PrettyStackTrace.h> // for pass list
#include <llvm/IR/LLVMContext.h>		// for llvm LLVMContext
#include <llvm/Support/SourceMgr.h> // for SMDiagnostic
//#include <llvm/Bitcode/BitcodeWriterPass.h>		// for createBitcodeWriterPass
#include <llvm/Bitcode/ReaderWriter.h>      // for createBitcodeWriterPass
#include <ctime>
#include <iostream>
#include <sys/time.h>
using namespace llvm;


static cl::opt<std::string> InputFilename(cl::Positional,
        cl::desc("<input bitcode>"), cl::init("-"));

//static cl::opt<bool>
//StandardCompileOpts("std-compile-opts",
  //                  cl::desc("Include the standard compile time optimizations"));

//static cl::list<const PassInfo*, bool, PassNameParser>
//PassList(cl::desc("Optimizations available:"));

/*
static cl::opt<bool> DAA("daa", cl::init(false),
                         cl::desc("Demand-Driven Alias Analysis Pass"));

static cl::opt<bool> REGPT("dreg", cl::init(false),
                           cl::desc("Demand-driven regular points-to analysis"));

static cl::opt<bool> RFINEPT("dref", cl::init(false),
                             cl::desc("Demand-driven refinement points-to analysis"));

static cl::opt<bool> ENABLEFIELD("fdaa", cl::init(false),
                                 cl::desc("enable field-sensitivity for demand-driven analysis"));

static cl::opt<bool> ENABLECONTEXT("cdaa", cl::init(false),
                                   cl::desc("enable context-sensitivity for demand-driven analysis"));

static cl::opt<bool> ENABLEFLOW("ldaa", cl::init(false),
                                cl::desc("enable flow-sensitivity for demand-driven analysis"));

*/

int main(int argc, char ** argv) {
    std::cout << __LINE__ << "\n";
#if 0
    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    analysisUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Demand-Driven Points-to Analysis\n");

    SVFModule svfModule(moduleNameVec);

    DDAPass *dda = new DDAPass();
    dda->runOnModule(svfModule);

    svfModule.dumpModulesToFile(".dvf");
#else
    sys::PrintStackTraceOnErrorSignal();
    llvm::PrettyStackTraceProgram X(argc, argv);

    LLVMContext &Context = getGlobalContext();

    std::string OutputFilename;

    cl::ParseCommandLineOptions(argc, argv, "Demand-Driven Points-to Analysis\n");
    sys::PrintStackTraceOnErrorSignal();

    PassRegistry &Registry = *PassRegistry::getPassRegistry();

    initializeCore(Registry);
    initializeScalarOpts(Registry);
    initializeIPO(Registry);
    initializeAnalysis(Registry);
    initializeTransformUtils(Registry);
    initializeInstCombine(Registry);
    initializeInstrumentation(Registry);
    initializeTarget(Registry);

    llvm::legacy::PassManager Passes;

    SMDiagnostic Err;

    // Load the input module...
    std::unique_ptr<Module> M1 = parseIRFile(InputFilename, Err, Context);

    if (!M1) {
        Err.print(argv[0], errs());
        return 1;
    }


    std::unique_ptr<tool_output_file> Out;
    std::error_code ErrorInfo;

    StringRef str(InputFilename);
    InputFilename = str.rsplit('.').first;
    OutputFilename = InputFilename + ".dvf";

    Out.reset(
        new tool_output_file(OutputFilename.c_str(), ErrorInfo,
                             sys::fs::F_None));

    if (ErrorInfo) {
        errs() << ErrorInfo.message() << '\n';
        return 1;
    }

    Passes.add(new DDAPass());

    Passes.add(createBitcodeWriterPass(Out->os()));

    Passes.run(*M1.get());
    Out->keep();

#endif

    return 0;

}

