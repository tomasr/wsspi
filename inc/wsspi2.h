//==============================================================================
// File: 			    wsspi2.h
//
// Description: 	contains the basic functionality of the WSSPI library
//
// Revisions: 		06/06/2000 - created
//                06/15/2000 - added NTLM support
//                07/07/2000 - modified the library creation, changed 
//                             inheritance pattern
//                09/07/2000 - added new accesors for Buffer and Context
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef WSSPI2_H__INCLUDED
#define WSSPI2_H__INCLUDED


#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#if defined(UNICODE)
#define _UNICODE
#endif

#if !defined(WSSPI_NO_WINHEADERS)
  #include <windows.h>
  #include <tchar.h>
  #include <exception>
  #include <string>
  #include <ostream>
  #include <vector>
  #include <assert.h>
  #include "wsync.h"

  #define SECURITY_WIN32
  #include <security.h>
  #include <schannel.h>
#endif // WSSPI_NO_WINHEADERS

//
// force link against our static lib
//
#if !defined(WSSPI_NO_AUTO_LINK)

#ifdef _DEBUG
  #ifdef UNICODE
    #pragma comment(lib, "wsspi21ud.lib")
  #else
    #pragma comment(lib, "wsspi21d.lib")
  #endif
#else
  #ifdef UNICODE
    #pragma comment(lib, "wsspi21u.lib")
  #else
    #pragma comment(lib, "wsspi21.lib")
  #endif
#endif 

#endif // WSSPI_NO_AUTO_LINK

// WSSPI VERSION
#define WSSPI_VERSION   0x0201


// we don't use virtual inheritance much, so
// no need for vtables in many classes
#define no_vtable __declspec(novtable)
// we can also improve some exception semantics
#define no_throw __declspec(nothrow)

namespace WSSPI2 {

// unicode/ansi definitions
#ifdef _UNICODE
  typedef std::wstring  wsstring;  
  typedef std::wostream wsostream;
#else
  typedef std::string   wsstring;
  typedef std::ostream  wsostream;
#endif

// include our files
  #include "sspiex.h"
  #include "sspilib.h"
  #include "sspipkg.h"
  #include "sspibuf.h"
  #include "sspicred.h"
  #include "sspictxt.h"
}

#endif // WSSPI2_H__INCLUDED
