//==============================================================================
// File: 			    sspiex.h
//
// Description: 	declaration of our exception class
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPIEX_H__INCLUDED
#define SSPIEX_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


// exception throwing macros
// default is throw by value
// #define WSSPI_EX_THROW_NEW
// to throw them using new
#ifndef WSSPI_EX_THROW_NEW
  #define throwex(x)    (throw SspiEx(x))
  #define throwexe(x,y) (throw SspiEx(x,y))
#else
  #define throwex(x)    (throw new SspiEx(x))
  #define throwexe(x,y) (throw new SspiEx(x,y))
#endif

/**
  Possible exceptions
*/
enum sspi_error {
  err_success =0,          // ok!
  err_not_init,            // sspi lib not initialized
  err_no_lib,              // provider dll not found
  err_no_pkg,              // no package with that name found
  err_pkg_enum_failed,     // package enumeration failed
  err_no_sec_interface,    // no security interface
  err_no_credentials,      // no credentials could be obtained
  err_no_memory,           // not enough memory
  err_auth_failed,         // unknown error while authenticating
  err_impersonate,         // impersonation failed
  err_revert_to_self,      // revert_to_self failed
  err_query_failed,        // failed query
  err_encrypt_failed,      // encryption failed
  err_decrypt_failed,      // decryption failed
  err_import_failed,       // failed to import security context
  err_export_failed,       // failed to export security context
  err_act_failed,          // ApplyControlToken() failed
  err_query_token_failed,  // QuerySecurityContextToken() failed
  err_unknown,             // unknown error
};



/**
  SspiEx is our exception class all exceptions 
  thrown by this library are of this type.
*/
class no_vtable SspiEx
{
public:
  SspiEx ( sspi_error err, HRESULT win32err = 0 );
  void Free ( );
  
  sspi_error Error ( ) const;
  DWORD Win32Err ( ) const;
  wsstring ErrorString ( ) const;
  wsstring Win32ErrString ( ) const;

private:
  //! library error code
  sspi_error  m_err;
  //! win32 error code
  HRESULT     m_win32err;
}; // class SspiEx

wsostream & operator<< ( wsostream & o, const SspiEx & e );

#endif // SSPIEX_H__INCLUDED
