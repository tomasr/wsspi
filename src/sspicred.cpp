//==============================================================================
// File: 			    sspicred.cpp
//
// Description: 	implementation of our credential classes
//
// Revisions: 		8/6/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#include "stdafx.h"

using namespace WSSPI2;

// unicode/ansi definitions
#ifdef _UNICODE
  #define USTR(str) ((unsigned short*)(str))
#else
  #define USTR(str) ((unsigned char*)(str))
#endif

//==============================================================================
// Credentials implementation

Credentials::Credentials ( )
  : m_target ( 0 ),
    m_use ( cu_both )
{
  SecInvalidateHandle ( &m_hCred );
}

void Credentials::Initialize ( 
      const SecPkg & pkg,
      credentials_use use, 
      const TCHAR * target /*= NULL */
    )
{
  m_use = use;
  m_pkg = pkg;
  if ( target != 0 )
  {
    m_target = _tcsdup ( target );
    if ( m_target == 0 ) throwex ( err_no_memory );
  }
}

Credentials::~Credentials ( )
{
  g_sspi->FreeCredentialsHandle ( &m_hCred );
  if ( m_target != 0 ) free ( m_target );
}

// == accessors ==
/**
  Is this instance valid?
*/
bool Credentials::IsValid ( ) const
{
  return (m_hCred.dwLower != -1 || m_hCred.dwUpper != -1);
}

/**
  Returns a reference to the package used
  to acquire these credentials
*/
const SecPkg & Credentials::Package ( ) const
{
  return m_pkg;
}


/**
  Returns a pointer to the Credentials handle
*/
PCredHandle Credentials::GetHandle ( )
{
  return &m_hCred;
}

/**
  Returns the Target used when acquiring these
  Credentials
*/
const TCHAR * Credentials::Target ( ) const
{
  return m_target;
}

/**
  Returns the name of the user these credentials
  represent. Some providers always return an empty 
  string (e.g. NTLM), while on others the function
  can just fail.
*/
wsstring Credentials::UserName ( ) const
{
  wsstring user = _T("");
  SecPkgCredentials_Names spcn;
  SECURITY_STATUS status = 0;

  status = g_sspi->QueryCredentialsAttributes ( 
                    &m_hCred,
                    SECPKG_CRED_ATTR_NAMES,
                    (void*)&spcn
                  );
  if ( status == SEC_E_OK && spcn.sUserName != 0)
  {
    user = spcn.sUserName;
    g_sspi->FreeContextBuffer ( spcn.sUserName );
  }
  return user;
}

/**
  Is the given algorithm supported?
*/
bool Credentials::SupportsAlgorithm ( ALG_ID id ) const
{
  SecPkgCred_SupportedAlgs scsa;
  SECURITY_STATUS status = 0;

  status = g_sspi->QueryCredentialsAttributes ( 
                    &m_hCred,
                    SECPKG_ATTR_SUPPORTED_ALGS,
                    (void*)&scsa
                  );
  bool supported = false;
  if ( status == SEC_E_OK )
  {
    // search for the specified algorithm
    for ( unsigned i = 0; i < scsa.cSupportedAlgs; i++ )
      if ( scsa.palgSupportedAlgs[i] == id )
        supported = true;
  
    g_sspi->FreeContextBuffer ( scsa.palgSupportedAlgs );
  }
  return supported;
}

/**
  Get minimum and maximum cypher strengths used
*/ 
void Credentials::GetCipherStrengths ( DWORD & min, DWORD & max ) const
{
  SecPkgCred_CipherStrengths sccs;
  SECURITY_STATUS status = 0;

  status = g_sspi->QueryCredentialsAttributes ( 
                    &m_hCred,
                    SECPKG_ATTR_CIPHER_STRENGTHS,
                    (void*)&sccs
                  );
  if ( status != SEC_E_OK )
  {
    min = sccs.dwMinimumCipherStrength;
    max = sccs.dwMaximumCipherStrength;
  }
  else min = max = 0;
}

/**
  Get supported protocols
*/
DWORD Credentials::GetProtocols ( ) const
{
  SecPkgCred_SupportedProtocols scsp;
  SECURITY_STATUS status = 0;

  status = g_sspi->QueryCredentialsAttributes ( 
                    &m_hCred,
                    SECPKG_ATTR_SUPPORTED_PROTOCOLS,
                    (void*)&scsp
                  );
  if ( status == SEC_E_OK )
    return scsp.grbitProtocol;
  else return 0;
}

//==============================================================================
// NtCredentials implementation

NtCredentials::NtCredentials (
        NtCredPkg pkg,
        Credentials::credentials_use use, 
        const TCHAR * target /* = NULL */
      )
{
  const TCHAR * pkgname = 0;
  switch ( pkg )
  {
  case nt_ntlm:      pkgname = _T("NTLM"); break;
  case nt_kerberos:  pkgname = _T("KERBEROS"); break;
  case nt_negotiate: pkgname = _T("NEGOTIATE"); break;
  }
  Initialize ( pkgname, use, target );
  m_identity.Version           = SEC_WINNT_AUTH_IDENTITY_VERSION;
  m_identity.Length            = sizeof m_identity;
  m_identity.Domain            = NULL;
  m_identity.DomainLength      = 0;
  m_identity.User              = NULL;
  m_identity.UserLength        = 0;
  m_identity.Password          = NULL;
  m_identity.PasswordLength    = 0;
  // we don't support passing in a possible list of packages
  // when using Negotiate, you can implement it, though, if you like.
  m_identity.PackageList       = NULL;
  m_identity.PackageListLength = 0;
}

NtCredentials::~NtCredentials( )
{
  if ( m_identity.Domain != NULL )
    free ( m_identity.Domain );
  if ( m_identity.User != NULL )
    free ( m_identity.User );
  if ( m_identity.Password != NULL )
    free ( m_identity.Password );
}

/**
  Acquire credentials for the current
  security context
*/
void NtCredentials::Acquire ( )
{
  SECURITY_STATUS     status;
  
  status = AcquireCredentials ( 
                NULL, NULL, NULL,
                NULL, NULL
              );
  if ( status != SEC_E_OK )
    throwexe ( err_no_credentials, status );
}

/**
  Acquire credentials for an alternate
  security context, based on domain\\user
  and its password.
*/
void NtCredentials::AcquireAlternate ( 
      const TCHAR * domain,
      const TCHAR * user,
      const TCHAR * password
    )
{
  SECURITY_STATUS     status;
  
  // set up credentials
  // only domain == NULL makes sense.
  // user and password must _not_ be NULL
  assert ( (user != NULL) && (password != NULL) );
  
  if ( domain != NULL )
  {
    m_identity.Domain         = USTR(_tcsdup ( domain));
    m_identity.DomainLength   = _tcslen ( domain );
  }
  m_identity.User           = USTR(_tcsdup ( user ));
  m_identity.UserLength     = _tcslen ( user );
  m_identity.Password       = USTR(_tcsdup ( password ));
  m_identity.PasswordLength = _tcslen ( password );
#ifdef _UNICODE
  m_identity.Flags          = SEC_WINNT_AUTH_IDENTITY_UNICODE;
#else
  m_identity.Flags          = SEC_WINNT_AUTH_IDENTITY_ANSI;
#endif

  status = AcquireCredentials ( 
                NULL, NULL, 
                &m_identity,
                NULL, NULL
              );
  if ( status != SEC_E_OK )
    throwexe ( err_no_credentials, status );
} 

/**
  Acquire credentials based on an exisiting 
  logon session id (LUID)
*/
void NtCredentials::AcquireAlternate ( const LUID * luid )
{
  SECURITY_STATUS     status;
  
  status = AcquireCredentials ( 
                NULL,
                const_cast<LUID*>(luid),
                NULL, NULL, NULL
              );
  if ( status != SEC_E_OK )
    throwexe ( err_no_credentials, status );
}

