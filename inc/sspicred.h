//==============================================================================
// File: 			    sspicred.h
//
// Description: 	declaration of our credential classes
//
// Revisions: 		8/6/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPICRED_H__INCLUDED
#define SSPICRED_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/**
  Credentials is our base class that 
  represents some security credentials. 
  It lacks, however, the specific functionality to 
  acquire those credentials, which is relegated to 
  its subclasses.
*/ 
class Credentials : protected SspiBase
{
public:
  //! credentials use
  enum credentials_use {
    cu_server = SECPKG_CRED_INBOUND,
    cu_client = SECPKG_CRED_OUTBOUND,
    cu_both   = SECPKG_CRED_BOTH,
  };

  virtual ~Credentials();

  // == accessors ==
  bool IsValid() const;
  const SecPkg & Package() const;
  PCredHandle GetHandle();
  const TCHAR * Target() const;
  wsstring UserName() const;
  bool SupportsAlgorithm ( ALG_ID id ) const;
  void GetCipherStrengths ( DWORD & min, DWORD & max ) const;
  DWORD GetProtocols() const;

protected:
  // make our constructor protected so that
  // we cannot be instantiated
  Credentials();
  void Initialize ( 
      const SecPkg & pkg,
      credentials_use use, 
      const TCHAR * target = NULL 
    );
  /**
    Acquire credentials wrapper It's templatized to add a
    little type safety over SSPI's AcquireCredentialsHandle()
    call, although it's not really much!
  */
  template <typename TAD, typename TKA>
  SECURITY_STATUS AcquireCredentials ( 
        TCHAR * principal,
        PLUID logon_id,
        TAD auth_data,
        SEC_GET_KEY_FN get_key_func,
        TKA gkf_argument
    )
  {
    TimeStamp expiration;
    return g_sspi->AcquireCredentialsHandle ( 
                  principal, 
                  const_cast<TCHAR*>(Package().Name().c_str()),
                  m_use, logon_id, 
                  (void*)auth_data,
                  get_key_func,
                  (void*)gkf_argument,
                  &m_hCred, &expiration
                );
  }

// make copy ctor and assigment private
// because there's no way to copy a CredHandle
private:
  Credentials ( const Credentials & cred );
  const Credentials & operator= ( const Credentials & cred );

private:
  credentials_use     m_use;
  SecPkg              m_pkg;
  TCHAR *             m_target;
  mutable CredHandle  m_hCred;
}; // class Credentials

/**
  NtCredentials implements the interface
  required to acquire credentials for the most 
  common Windows NT packages:
  <ul>
    <li>NTLM
    <li>Kerberos
    <li>Negotiate
  <ul>
  
  You just need to specify the package (NTLM by default)
  and the usual parameters if you need to acquire alternate
  credentials.
*/
class NtCredentials : public Credentials
{
public:
  enum NtCredPkg {
    nt_ntlm,
    nt_kerberos,
    nt_negotiate,
  };
  NtCredentials (
      NtCredPkg pkg, 
      Credentials::credentials_use use, 
      const TCHAR * target = NULL 
    );
  virtual ~NtCredentials( );

  void Acquire ( );
  void AcquireAlternate ( 
        const TCHAR * domain,
        const TCHAR * user,
        const TCHAR * password
      );
  void AcquireAlternate ( const LUID * luid );

private:
  SEC_WINNT_AUTH_IDENTITY_EX m_identity;
   
}; // class NtCredentials

#endif // SSPICRED_H__INCLUDED
