//==============================================================================
// File: 			    sspiex.cpp
//
// Description: 	implementation of our exception class
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#include "stdafx.h"


using namespace WSSPI2;

SspiEx::SspiEx ( sspi_error err, HRESULT win32err /*= 0*/ )
  : m_err ( err ),
    m_win32err ( win32err )
{
}

/**
  Deletes this exception instance.
  Use only if you #defined WSSPI_EX_THROW_NEW
*/
void SspiEx::Free ( )
{
  delete this;
}

/**
  Returns the library error that caused this exception

*/
sspi_error SspiEx::Error ( ) const
{
  return m_err;
}
/**
  Returns the Win32 HRESULT that caused this exception

*/
DWORD SspiEx::Win32Err ( ) const
{
  return m_win32err;
}

/**
  Returns a string with the library error

*/
wsstring SspiEx::ErrorString ( ) const
{
  static struct {
    sspi_error    code;
    const TCHAR * str;
  } errmap[] = {
    { err_success,            _T("ok") },
    { err_not_init,           _T("sspi lib not initialized") },
    { err_no_lib,             _T("provider dll not found") },
    { err_no_pkg,             _T("no package with that name found") },
    { err_pkg_enum_failed,    _T("package enumeration failed") },
    { err_no_sec_interface,   _T("no security interface") },
    { err_no_credentials,     _T("no credentials could be obtained") },
    { err_no_memory,          _T("not enough memory") },
    { err_auth_failed,        _T("unknown error while authenticating") },
    { err_impersonate,        _T("impersonation failed") },
    { err_revert_to_self,     _T("revert_to_self failed") },
    { err_query_failed,       _T("query failed") },
    { err_encrypt_failed,     _T("encryption failed") },
    { err_decrypt_failed,     _T("decryption failed") },
    { err_import_failed,      _T("failed to import security context") },
    { err_export_failed,      _T("failed to export security context") },
    { err_act_failed,         _T("ApplyControlToken() failed") },
    { err_query_token_failed, _T("QuerySecurityContextToken() failed")},
    { err_unknown,            _T("unknown error") }
  };
  assert (m_err <= err_unknown );
  return wsstring(errmap[m_err].str);
}

/**
  Return a string with the Win32 error description,
  as returned by FormatMessage()
*/
wsstring SspiEx::Win32ErrString ( ) const
{
  wsstring str;
  LPTSTR buf = NULL;
  
  FormatMessage ( 
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
      | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, m_win32err, GetUserDefaultLangID( ),
      (LPTSTR)&buf, 0, NULL
    );
  if ( buf != 0 ) 
  {
    str = buf;
    LocalFree ( buf );
  }
  return str;
}

/**
  Dumps this exception object
*/
wsostream & WSSPI2::operator<< ( wsostream & o, const SspiEx & e )
{
  o << _T("Exception: ") << e.ErrorString() << std::endl 
    << _T("  Win32Err: 0x") << std::hex << e.Win32Err() 
    << _T("  ") << e.Win32ErrString() << std::endl;
  return o;
}
