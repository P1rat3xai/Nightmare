// Nightmare.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "Nightmare.h"


// This is an example of an exported variable
NIGHTMARE_API int nNightmare=0;

// This is an example of an exported function.
NIGHTMARE_API int fnNightmare(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CNightmare::CNightmare()
{
    return;
}
