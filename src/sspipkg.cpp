//==============================================================================
// File: 			    sspipkg.cpp
//
// Description: 	implementation of our package support classes
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#include "stdafx.h"

using namespace WSSPI2;

//==============================================================================
// SecPkg implementation

SecPkg::SecPkg ( const TCHAR * pkgname /*= NULL*/ )
  : m_have_pkg ( false )
{      
  SECURITY_STATUS status;
  
  if ( pkgname != NULL )
  {
    SecPkgInfo * pkg = NULL;
    status = g_sspi->QuerySecurityPackageInfo ( 
                const_cast<TCHAR*>(pkgname),
                &pkg
              );
    if ( status != SEC_E_OK )
      throwexe ( err_no_pkg, status );
    if ( !GetLocalCopy ( pkg ) )
      throwex ( err_no_pkg );
    if ( g_sspi->FreeContextBuffer != NULL )
      g_sspi->FreeContextBuffer ( (void*) pkg );
  }
}

SecPkg::SecPkg ( const SecPkgInfo * pkg )
{
  assert ( pkg != 0 );
  if ( !GetLocalCopy ( pkg ) )
    throwex ( err_no_pkg );
}

SecPkg::~SecPkg ( )
{
  Free ( );
}

// == copy contruction/assignment ==
SecPkg::SecPkg ( const SecPkg & pkg )
{
  if ( !pkg.IsValid ( ) || !GetLocalCopy ( &pkg.m_info ) )
    throwex ( err_no_pkg );
}
SecPkg & SecPkg::operator= ( const SecPkg & pkg )
{
  if ( this != &pkg )
  {
    if ( !pkg.IsValid ( )  || !GetLocalCopy ( &pkg.m_info ) )
      throwex ( err_no_pkg );
  }
  return *this;
}

// == accessors ==
/**
  Checks if the package supports the 
  capabilities set
*/
bool SecPkg::HasCapabilities ( ULONG caps ) const
{
  return ((m_info.fCapabilities & caps) == caps);
}

/**
  Returns the package version number
*/
USHORT SecPkg::Version ( ) const
{
  if ( !IsValid ( ) )
    throwex ( err_no_pkg );
  return m_info.wVersion;
}
/**
  Returns the package RPC identifier
*/
USHORT SecPkg::RpcId ( ) const
{
  if ( !IsValid ( ) )
    throwex ( err_no_pkg );
  return m_info.wRPCID;
}
/**
  Returns the maximum token size supported by 
  the package. This is used to allocate 
  buffers of the necessary size.
*/
ULONG SecPkg::MaxTokenSize ( ) const
{
  if ( !IsValid ( ) )
    throwex ( err_no_pkg );
  return m_info.cbMaxToken;
}
/**
  Returns the package name
*/
wsstring SecPkg::Name ( ) const
{
  if ( !IsValid ( ) )
    throwex ( err_no_pkg );
  return wsstring(m_info.Name);
}
/**
  Returns the package comment
*/
wsstring SecPkg::Comment ( ) const
{
  if ( !IsValid ( ) )
    throwex ( err_no_pkg );
  return wsstring(m_info.Comment);
}
/**
  Returns true if this is a valid 
  package instance.
*/
bool SecPkg::IsValid ( ) const
{
  return m_have_pkg;
}

// == operators ==
int SecPkg::operator== ( const SecPkg & pkg ) const
{
  return (Name() == pkg.Name());
}
int SecPkg::operator== ( const wsstring & pkgname ) const
{
  return (Name() == pkgname);
}

int SecPkg::operator!= ( const SecPkg & pkg ) const
{
  return !(Name() == pkg.Name());
}
int SecPkg::operator!= ( const wsstring & pkgname ) const
{
  return !(Name() == pkgname);
}


/**
  Allocates a private copy of the SecPkgInfo
  struct.
*/
bool SecPkg::GetLocalCopy ( const SecPkgInfo * pkg )
{
  memcpy ( (void*)&m_info, (void*)pkg, sizeof SecPkgInfo );
  m_info.Name = _tcsdup ( pkg->Name );
  if ( m_info.Name != 0 )
  {
    m_info.Comment = _tcsdup ( pkg->Comment );
    if ( m_info.Comment != 0 )
    {
      m_have_pkg = true;
      return true;
    }
    free ( m_info.Name );
  }
  m_have_pkg = false;
  return false;
}

/**
  Release internal data
*/
void SecPkg::Free ( )
{
  if ( m_have_pkg )
  {
    free ( m_info.Name );
    free ( m_info.Comment );
  }
  m_have_pkg = false;
}


// == dumper ==
wsostream & WSSPI2::operator<< ( wsostream & o, const SecPkg & p )
{
  // capabilities flags
  static struct 
  {
    DWORD         cap;        // capability
    const TCHAR*  comment;    // name and comment
  } caps[] = {
    { SECPKG_FLAG_INTEGRITY,         _T("SECPKG_FLAG_INTEGRITY: Supports message integrity.") },
    { SECPKG_FLAG_PRIVACY,           _T("SECPKG_FLAG_PRIVACY: Supports message encription.") },
    { SECPKG_FLAG_TOKEN_ONLY,        _T("SECPKG_FLAG_TOKEN_ONLY: Only supports SECBUFFER_TOKEN buffers.") },
    { SECPKG_FLAG_DATAGRAM,          _T("SECPKG_FLAG_DATAGRAM: Supports datagram-oriented authentication.") },
    { SECPKG_FLAG_CONNECTION,        _T("SECPKG_FLAG_CONNECTION: Supports connection-oriented authentication.") },
    { SECPKG_FLAG_MULTI_REQUIRED,    _T("SECPKG_FLAG_MULTI_REQUIRED: Multiple legs are required for authentication.") },
    { SECPKG_FLAG_CLIENT_ONLY,       _T("SECPKG_FLAG_CLIENT_ONLY: Server authentication support is not provided.") },
    { SECPKG_FLAG_EXTENDED_ERROR,    _T("SECPKG_FLAG_EXTENDED_ERROR:  Supports extended error handling.") },
    { SECPKG_FLAG_IMPERSONATION,     _T("SECPKG_FLAG_IMPERSONATION: Supports Win32 impersonation in server contexts.") },
    { SECPKG_FLAG_ACCEPT_WIN32_NAME, _T("SECPKG_FLAG_ACCEPT_WIN32_NAME: Understands Win32 principal and target names.") },
    { SECPKG_FLAG_STREAM,            _T("SECPKG_FLAG_STREAM: Supports stream semantics.") },
    { 0xFFFFFFFF,                    _T("") }
  };
  o << _T("Package: ") << p.Name ( ) << std::endl
    << _T("Description: ") << p.Comment ( ) << std::endl
    << _T("Capabilities: ") << std::endl;
  
  for ( int i = 0; caps[i].cap != 0xFFFFFFFF; ++i )
  {
    if ( p.HasCapabilities ( caps[i].cap ) )
      o << caps[i].comment << std::endl;
  }
  return o;
} // end operator<<

//==============================================================================
// PkgList implementation

PkgList::PkgList ( )
{
  SECURITY_STATUS status;
  SecPkgInfo *    packages = 0;
  ULONG           numpkgs = 0;
  
  SspiLib & sspi = SspiLib::Instance ( );
  if ( sspi->EnumerateSecurityPackages == NULL )
    throwex ( err_no_sec_interface );
  
  status = sspi->EnumerateSecurityPackages (
                &numpkgs,
                &packages
              );
  if ( status != SEC_E_OK )
    throwexe ( err_pkg_enum_failed, status );
  
  // build the list
  for ( ULONG i = 0; i < numpkgs; i++ )
    push_back ( SecPkg(&packages[i]) );
  
  if ( sspi->FreeContextBuffer != NULL )
    sspi->FreeContextBuffer ( (void*)packages );

  sspi.Release ( );
}
