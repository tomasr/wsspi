//==============================================================================
// File: 			    sspilib.cpp
//
// Description: 	implementation of our library object
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#include "stdafx.h"

using namespace WSSPI2;

// unicode/ansi definitions
#ifdef _UNICODE
  #define INIT_SEC_INTERFACE_NAME       "InitSecurityInterfaceW"
#else
  #define INIT_SEC_INTERFACE_NAME       "InitSecurityInterfaceA"
#endif

// static objects
using namespace Winterdom::Runtime;
Threading::CriticalSection SspiLib::m_lock;
SspiLib * SspiLib::m_instance = 0;


SspiLib::SspiLib ( )
  : m_fpt ( 0 ),
    m_hModule ( 0 ),
    m_refcount ( 0 )
{
  m_hModule = LoadLibrary ( _T("security.dll") );
  if ( m_hModule == 0 )
  {
    // try with secur32.dll instead
    m_hModule = LoadLibrary ( _T("secur32.dll") );
    if ( m_hModule == 0 )
      throwexe ( err_no_lib, HRESULT_FROM_WIN32(GetLastError ( )) );
  }

  INIT_SECURITY_INTERFACE isi;
  isi = (INIT_SECURITY_INTERFACE)GetProcAddress ( 
            m_hModule, INIT_SEC_INTERFACE_NAME
        );
  if ( isi == 0 )
    throwexe ( err_no_lib, HRESULT_FROM_WIN32(GetLastError ( )) );

  m_fpt = isi ( );
  if ( m_fpt == 0 )
    throwexe ( err_no_lib, HRESULT_FROM_WIN32(GetLastError ( )) );
}

SspiLib::~SspiLib ( )
{
  m_fpt = 0;
  m_refcount = 0;
  FreeLibrary ( m_hModule );
}

/**
  Decrements the reference count on the library object.

  Note: If you derive from SspiBase, its destructor
  dows it for you.
*/
void SspiLib::Release ( )
{
  if ( ::InterlockedDecrement ( &m_refcount ) == 0 )
    delete this;
}
void SspiLib::AddRef ( )
{
  ::InterlockedIncrement ( &m_refcount );
}

PSecurityFunctionTable SspiLib::operator-> ( )
{ 
  return m_fpt; 
}

SspiLib & SspiLib::Instance ( )
{
  if ( !m_instance )
  {
    Threading::CriticalSectionLock autolock(m_lock);
      if ( !m_instance )
        m_instance = new SspiLib;
  }
  m_instance->AddRef ( );
  return *m_instance;
}
