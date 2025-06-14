// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the NIGHTMARE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// NIGHTMARE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef NIGHTMARE_EXPORTS
#define NIGHTMARE_API __declspec(dllexport)
#else
#define NIGHTMARE_API __declspec(dllimport)
#endif

// This class is exported from the dll
class NIGHTMARE_API CNightmare {
public:
	CNightmare(void);
	// TODO: add your methods here.
};

extern NIGHTMARE_API int nNightmare;

NIGHTMARE_API int fnNightmare(void);
