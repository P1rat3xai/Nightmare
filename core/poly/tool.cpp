#include <clang/AST/AST.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <clang/Rewrite/Core/Rewriter.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

using namespace clang;
using namespace clang::tooling;
using namespace clang::ast_matchers;

class RenameFunction : public MatchFinder::MatchCallback {
public:
    Rewriter &Rewrite;

    RenameFunction(Rewriter &R) : Rewrite(R) {}

    void run(const MatchFinder::MatchResult &Result) override {
        if (const FunctionDecl *FD = Result.Nodes.getNodeAs<FunctionDecl>("func")) {
            if (FD->getNameAsString() == "add") {
                Rewrite.ReplaceText(FD->getLocation(), FD->getNameAsString().length(), "calc");
            }
        }
    }
};

int main(int argc, const char **argv) {
    CommonOptionsParser OptionsParser(argc, argv);
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    Rewriter Rewrite;
    RenameFunction RenameCallback(Rewrite);
    MatchFinder Finder;

    Finder.addMatcher(functionDecl().bind("func"), &RenameCallback);

    class ToolAction : public ASTFrontendAction {
    public:
        Rewriter &Rewrite;
        ToolAction(Rewriter &R) : Rewrite(R) {}

        void EndSourceFileAction() override {
            Rewrite.getEditBuffer(Rewrite.getSourceMgr().getMainFileID()).write(llvm::outs());
        }

        std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef) override {
            Rewrite.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
            return Finder.newASTConsumer();
        }

        MatchFinder Finder;
    };

    return Tool.run(newFrontendActionFactory<ToolAction>(&Rewrite).get());
}
