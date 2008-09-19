//==============================================================================
// File: 			    sspictxt.h
//
// Description: 	definitions of our context classes
//
// Revisions: 		8/6/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPICTXT_H__INCLUDED
#define SSPICTXT_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/** 
 what's the current state
 of the authentication process?
*/
enum auth_state {
  as_ok       =0,   // authentication succeeded
  as_denied   =1,   // authentication failed (user/pwd rejected)
  as_continue =2,   // go another round
  as_error    =3,   // unknown error (you´ll never see it)
};

/**
  Context is the base class for our server 
  and client classes. It wraps all the 
  functionality that's shared by both 
  sides of the authentication solution.
*/
class Context : protected SspiBase
{
public:
  virtual ~Context ( );

  void SetCredentials ( Credentials & cred );

  bool IsValid ( ) const;
  PCtxtHandle GetHandle ( );
  void SetWorkingParams ( ULONG ctxt_reqs, ULONG data_rep );
  void Free ( );

  // == query attributes wrappers
  ULONG MaxTokenSize ( ) const;
  ULONG MaxSignatureSize ( ) const;
  ULONG BlockSize ( ) const;
  ULONG SecurityTrailerSize ( ) const;
  ULONG StreamHeaderSize ( ) const;
  ULONG StreamTrailerSize ( ) const;
  ULONG StreamMaxMessageSize ( ) const;
  ULONG StreamNumBuffers ( ) const;
  //    SecPkgContext_Names
  wsstring UserName ( ) const;
  wsstring AuthorityName ( ) const;
  //    SecPkgContext_KeyInfo
  wsstring SignatureAlgName ( ) const;
  wsstring EncryptAlgName ( ) const;
  ULONG KeySize ( ) const;
  ALG_ID SignatureAlgorithm ( ) const;
  ALG_ID EncryptAlgorithm ( ) const;
  void GetLifeSpan ( TimeStamp & start, TimeStamp & expiration ) const;
  
  // == message security ==
  void EncryptMessage ( ULONG qop, BufferDesc & msg, ULONG seq_num = 0 );
  void DecryptMessage ( ULONG & qop, BufferDesc & msg, ULONG seq_num = 0 );

  // == signature support ==
  void MakeSignature ( ULONG qop, BufferDesc & msg, ULONG seq_num = 0 );
  void VerifySignature ( ULONG & qop, BufferDesc & msg, ULONG seq_num = 0 );

  // == importing/exporting security contexts ==
  void Import ( Buffer & ctxt );
  void Export ( Buffer & ctxt );

  // == token stuff ==
  void ApplyControlToken ( Buffer & token );
  HANDLE QueryToken ( );

  // == authentication ==
  auth_state Authenticate ( Buffer * in, Buffer * out );

protected:
    Context ( );

private:
  template <class B> SECURITY_STATUS 
  no_throw QueryAttributes ( ULONG attr, B * buf ) const
  {
    assert ( buf != 0 );
    return g_sspi->QueryContextAttributes (
                  &m_hCtxt,
                  attr,
                  (void*)buf
                );
  }

  virtual SECURITY_STATUS CreateContext ( 
          PCtxtHandle old_ctxt, PSecBufferDesc ibd,
          PCtxtHandle new_ctxt, PSecBufferDesc obd
        ) =0;

protected:
          ULONG         m_ctxt_reqs;
          ULONG         m_data_rep;
          Credentials * m_cred;
          auth_state    m_state;
private:
          bool          m_have_ctxt;
  mutable CtxtHandle    m_hCtxt;
}; // class Context


/**
  ClientContext represents the client side 
  of the authentication solution (the client 
  security context). 
  ClientContext has no need (and shouldn't have) 
  for a destructor!
*/
class ClientContext : public Context
{
private:
  virtual SECURITY_STATUS CreateContext ( 
              PCtxtHandle old_ctxt, PSecBufferDesc ibd,
              PCtxtHandle new_ctxt, PSecBufferDesc obd
            );
}; // class ClientContext


/**
  ServerContext represents the server side
  of the suthentication solution (the server 
  security context). 
  ServerContext has no need (and shouldn't have) 
  for a destructor!
*/
class ServerContext : public Context
{
private:
  virtual SECURITY_STATUS CreateContext ( 
              PCtxtHandle old_ctxt, PSecBufferDesc ibd,
              PCtxtHandle new_ctxt, PSecBufferDesc obd
            );

public:
  // login confirmation
  void ConfirmAuthentication ( Buffer & buf );

  // == impersonation support ==
  void ImpersonateClient ( );
  void RevertToSelf ( );
}; // class ServerContext

#endif // SSPICTXT_H__INCLUDED
