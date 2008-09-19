
//
// wctypes.h: This header declares the basic types
//            
// This file is part of the Winterdom library
// Copyright (C) 2000-2001, Tomas Restrepo (tomasr@mvps.org)
//            
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//

#ifndef WCTYPES_H__INCLUDED
#define WCTYPES_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef UNICODE
   #define _UNICODE
#endif


#include <windows.h>
#include <cstdio>
#include <tchar.h>
#include <exception>
#include <cassert>
#include <process.h>
#include <map>
#include <string>
#include <stdexcept>

#ifdef UNICODE
   typedef std::wstring ustring;
#else
   typedef std::string ustring;
#endif  // UNICODE

//
// these definitions work for a
// 32-bit system 
//
#ifdef _32BIT_MACHINE
typedef unsigned char    byte;
typedef unsigned short   word;
typedef unsigned long    dword;

#ifdef _MSC_VER
typedef unsigned __int64 qword;
typedef __int64 long64;
#else
typedef unsigned long long qword;
typedef long long long64;
#endif // _MSC_VER



#endif // _32BIT_MACHINE

#endif // WCTYPES_H__INCLUDED
