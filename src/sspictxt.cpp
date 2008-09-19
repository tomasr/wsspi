//==============================================================================
// File: 			    sspictxt.cpp
//
// Description: 	implementation of our context classes
//
// Revisions: 		8/6/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#include "stdafx.h"

using namespace WSSPI2;


// default context requirements and data representation

namespace {
  const ULONG CTXT_REQS = ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT 
                          | ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE;
  const ULONG DATA_REP  = SECURITY_NATIVE_DREP;
}

Context::Context ( )
  : m_have_ctxt ( false ),
    m_state ( as_continue ),
    m_cred ( 0 ),
    m_ctxt_reqs ( CTXT_REQS ),
    m_data_rep ( DATA_REP )
{
  SecInvalidateHandle ( &m_hCtxt );
}

/**
  Destroys *this

  The destructor does not have to be virtual, because
  you'll never use Context by itself, you'll always use a
  derived class, and they are not really meant to be 
  polymorphic (IOW, you'll never delete an object of a 
  derived type through a pointer to Context).
*/
Context::~Context ( )
{
  Free ( );
}

/**
  Sets the credentials we'll be using. You should acquire
  the credentals before passing them in. Also, you need to
  keep the credentials alive as long as this Context 
  exists (easily done).
*/
void Context::SetCredentials ( Credentials & cred )
{
  assert ( cred.IsValid ( ) );
  m_cred = &cred;
}

/**
  Is this valid context?
*/
bool Context::IsValid ( ) const
{
  return (m_have_ctxt && m_state == as_ok);
}

/**
  Returns a pointer to our context handle.
*/
PCtxtHandle Context::GetHandle ( )
{
  return &m_hCtxt;
}

/**
  Sets the working parameters:
  <ul>
    <li>the context requirements, and
    <li>the data representation
  </ul>
*/
void Context::SetWorkingParams ( ULONG ctxt_reqs, ULONG data_rep )
{
  m_ctxt_reqs = ctxt_reqs;
  m_data_rep  = data_rep;
}


/**
  Releases this Context. This is very useful when you need
  to reuse a Context instance, such as when used in a server
  app.
  If you don't need this functionality, you don't need 
  to call Free() explicitly, as it will be called for you 
  during destruction.
*/
void Context::Free ( )
{
  g_sspi->DeleteSecurityContext ( &m_hCtxt );
  SecInvalidateHandle ( &m_hCtxt );
  m_have_ctxt = false;
  m_state = as_continue; 
}

// == query attributes wrappers
/**
  Returns the maximum token size used in the
  authentication process. It's not always reliable, though.
  
  Be wary of the value returned, and
  don't confuse it with SecPkg::MaxTokenSize()
*/
ULONG Context::MaxTokenSize ( ) const
{
  SecPkgContext_Sizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbMaxToken;
  else return 0;
}

/**
  Returns the maximum signature size this 
  context can deal with.
*/
ULONG Context::MaxSignatureSize ( ) const
{
  SecPkgContext_Sizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbMaxSignature;
  else return 0;
}

/**
  Returns the preferred block size for 
  encryption/decryption. To speed things up,
  you should provide data buffers with a size 
  that's an exact multiple of the BlockSize.
*/
ULONG Context::BlockSize ( ) const
{
  SecPkgContext_Sizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbBlockSize;
  else return 0;
}

/**
  Returs the buffer size needed to hold a
  security trailer.
*/
ULONG Context::SecurityTrailerSize ( ) const
{
  SecPkgContext_Sizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbSecurityTrailer;
  else return 0;
}

/**
  Returns the buffer size needed to hold a message
  header on a stream-oriented context.
*/
ULONG Context::StreamHeaderSize ( ) const
{
  SecPkgContext_StreamSizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_STREAM_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbHeader;
  else return 0;
}

/**
  Returns the buffer size needed to hold a message
  trailer on a stream-oriented context.
*/
ULONG Context::StreamTrailerSize ( ) const
{
  SecPkgContext_StreamSizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_STREAM_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbTrailer;
  else return 0;
}

/**
  Returns the maximum buffer size supported
  for messages on a stream-oriented context.
*/
ULONG Context::StreamMaxMessageSize ( ) const
{
  SecPkgContext_StreamSizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_STREAM_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cbMaximumMessage;
  else return 0;
}

/**
  Returns the minimum number of buffers needed
  on a stream-oriented context to do things like
  message signing and encryption.
*/
ULONG Context::StreamNumBuffers ( ) const
{
  SecPkgContext_StreamSizes sizes = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_STREAM_SIZES, &sizes );
  if ( status == SEC_E_OK )
    return sizes.cBuffers;
  else return 0;
}

//    SecPkgContext_Names
/**
  Returns the user name this security context represents.
  Not all provider return meaningful data here, though.
*/
wsstring Context::UserName ( ) const
{
  SecPkgContext_Names names = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_NAMES, &names );
  wsstring name = _T("");
  if ( status == SEC_E_OK && names.sUserName != 0 )
  {
    name = names.sUserName;
    g_sspi->FreeContextBuffer ( (void*)names.sUserName );
  }
  return name;
}

/**
  Returns the authority name used to establish this
  security context. Not all providers support this
  call.
*/
wsstring Context::AuthorityName ( ) const
{
  SecPkgContext_Authority names = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_AUTHORITY, &names );
  wsstring name = _T("");
  if ( status == SEC_E_OK && names.sAuthorityName != 0 )
  {
    name = names.sAuthorityName;
    g_sspi->FreeContextBuffer ( (void*)names.sAuthorityName );
  }
  return name;
}
//    SecPkgContext_KeyInfo
/**
  Returns the name of the algorithm used to 
  sign messages.
*/
wsstring Context::SignatureAlgName ( ) const
{
  SecPkgContext_KeyInfo info = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_KEY_INFO, &info );
  wsstring name = _T("");
  if ( status == SEC_E_OK && info.sSignatureAlgorithmName != 0 )
  {
    name = info.sSignatureAlgorithmName;
    g_sspi->FreeContextBuffer ( (void*)info.sSignatureAlgorithmName );
    g_sspi->FreeContextBuffer ( (void*)info.sEncryptAlgorithmName );
  }
  return name;
}

/**
  Returns the name of the algorithm used to
  encrypt messages.
*/
wsstring Context::EncryptAlgName ( ) const
{
  SecPkgContext_KeyInfo info = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_KEY_INFO, &info );
  wsstring name = _T("");
  if ( status == SEC_E_OK && info.sEncryptAlgorithmName != 0 )
  {
    name = info.sEncryptAlgorithmName;
    g_sspi->FreeContextBuffer ( (void*)info.sSignatureAlgorithmName );
    g_sspi->FreeContextBuffer ( (void*)info.sEncryptAlgorithmName );
  }
  return name;
}

/**
  Returns the size of the Key used to 
  encrypt/sign messages.
*/
ULONG Context::KeySize ( ) const
{
  SecPkgContext_KeyInfo info = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_KEY_INFO, &info );
  if ( status == SEC_E_OK )
  {
    g_sspi->FreeContextBuffer ( (void*)info.sSignatureAlgorithmName );
    g_sspi->FreeContextBuffer ( (void*)info.sEncryptAlgorithmName );
    return info.KeySize;
  }
  return 0;
}

/**
  Returns the id of the message-signing algorithm.
*/
ALG_ID Context::SignatureAlgorithm ( ) const
{
  SecPkgContext_KeyInfo info = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_KEY_INFO, &info );
  if ( status == SEC_E_OK )
  {
    g_sspi->FreeContextBuffer ( (void*)info.sSignatureAlgorithmName );
    g_sspi->FreeContextBuffer ( (void*)info.sEncryptAlgorithmName );
    return info.SignatureAlgorithm;
  }
  return 0;
}
/**
  Returns the id of the encryption algorithm.
*/
ALG_ID Context::EncryptAlgorithm ( ) const
{
  SecPkgContext_KeyInfo info = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_KEY_INFO, &info );
  if ( status == SEC_E_OK )
  {
    g_sspi->FreeContextBuffer ( (void*)info.sSignatureAlgorithmName );
    g_sspi->FreeContextBuffer ( (void*)info.sEncryptAlgorithmName );
    return info.EncryptAlgorithm;
  }
  return 0;
}

/**
  Returns the start and expiration time
  of this context's lifespan
*/
void Context::GetLifeSpan ( TimeStamp & start, TimeStamp & expiration ) const
{
  start.LowPart  = expiration.LowPart  = 0;
  start.HighPart = expiration.HighPart = 0; 

  SecPkgContext_Lifespan ls = { 0x0 };
  SECURITY_STATUS status = 0;
  status = QueryAttributes ( SECPKG_ATTR_LIFESPAN, &ls );
  if ( status == SEC_E_OK )
  {
    start      = ls.tsStart;
    expiration = ls.tsExpiry;
  }
}

// == message security ==
/**
  Encrypts a message with this security context.
*/
void Context::EncryptMessage ( ULONG qop, BufferDesc & msg, ULONG seq_num /*= 0*/ )
{
  if ( g_sspi->EncryptMessage == 0 ) 
    throwex ( err_no_sec_interface );

  SECURITY_STATUS status = 0;
  status = g_sspi->EncryptMessage ( 
                &m_hCtxt,
                qop,
                msg.get_bd ( ),
                seq_num
              );
  if ( status != SEC_E_OK )
  {
    if ( status == SEC_I_RENEGOTIATE )
      Free ( );
    throwexe ( err_encrypt_failed, status );
  }
  msg.update ( );
} //EncryptMessage()

/**
  Decrypts a message with this security context.
*/
void Context::DecryptMessage ( ULONG & qop, BufferDesc & msg, ULONG seq_num /*= 0*/ )
{
  if ( g_sspi->DecryptMessage == 0 ) 
    throwex ( err_no_sec_interface );

  SECURITY_STATUS status = 0;
  status = g_sspi->DecryptMessage ( 
                &m_hCtxt,
                msg.get_bd ( ),
                seq_num,
                &qop
              );
  if ( status != SEC_E_OK )
  {
    if ( status == SEC_I_RENEGOTIATE )
      Free ( );
    throwexe ( err_decrypt_failed, status );
  }
  msg.update ( );
} // DecryptMessage()

// == signature support ==
/**
  Signs a message with this security context.
*/
void Context::MakeSignature ( ULONG qop, BufferDesc & msg, ULONG seq_num /*= 0*/ )
{
  if ( g_sspi->MakeSignature == 0 ) 
    throwex ( err_no_sec_interface );

  SECURITY_STATUS status = 0;
  status = g_sspi->MakeSignature ( 
                &m_hCtxt,
                qop,
                msg.get_bd ( ),
                seq_num
              );
  if ( status != SEC_E_OK )
    throwexe ( err_encrypt_failed, status );
  msg.update ( );
} // MakeSignature()

//
// add extra checking code
//
/**
  Verifies that a message signature is correct.
*/
void Context::VerifySignature ( ULONG & qop, BufferDesc & msg, ULONG seq_num /*= 0*/ )
{
  if ( g_sspi->VerifySignature == 0 ) 
    throwex ( err_no_sec_interface );

  SECURITY_STATUS status = 0;
  status = g_sspi->VerifySignature ( 
                &m_hCtxt,
                msg.get_bd ( ),
                seq_num,
                &qop
              );
  if ( status != SEC_E_OK )
    throwexe ( err_encrypt_failed, status );
  msg.update ( );
} // VerifySignature()


// == importing/exporting security contexts ==
/**
  Imports a security context exported remotely by 
  Context::Export(). If this is a valid security context
  already, we release it.
*/
void Context::Import ( Buffer & ctxt )
{
  assert ( ctxt.Size( ) != 0 );

  // make sure we don't leak a context!
  Free ( );

  // copy string to a buffer
  // yuck!
  wsstring name = m_cred->Package().Name ( );
  TCHAR * str = new TCHAR[name.size()+1];
  if ( str == 0 ) throwex ( err_no_memory );
  _tcscpy ( str, name.c_str() );

  SECURITY_STATUS status = 0;
  status = g_sspi->ImportSecurityContext (
                str,
                ctxt.GetSecBuffer ( ),
                NULL,
                &m_hCtxt
              );

  delete [] str;
  if ( status != SEC_E_OK )
    throwexe ( err_import_failed, status );
  m_have_ctxt = true;
} // Import()

/**
  Exports this security context into a buffer, which
  can be later recreated by Context::Import().
*/
void Context::Export ( Buffer & ctxt )
{
  assert ( IsValid ( ) );

  // the buffer should be empty
  ctxt.Free ( );
  ctxt.SetOwner ( bo_sspi );

  SECURITY_STATUS status = 0;
  status = g_sspi->ExportSecurityContext (
                &m_hCtxt, 0,
                ctxt.GetSecBuffer ( ),
                NULL                    
              );

  if ( status != SEC_E_OK )
    throwexe ( err_export_failed, status );
} // Export()

// == token stuff ==
/**
  Establishes this security context from a 
*/
void Context::ApplyControlToken ( Buffer & token )
{
  assert ( token.IsValid ( ) );

  BufferDesc bd;
  bd.add ( &token );

  SECURITY_STATUS status = 0;
  status = g_sspi->ApplyControlToken (
                &m_hCtxt,
                bd.get_bd ( )
              );
  if ( status != SEC_E_OK )
    throwexe ( err_act_failed, status );            
  m_have_ctxt = true;
}

/**
  Returns a handle to the token that
  represents this security context. You should
  free this handle later with CloseHandle().
*/
HANDLE Context::QueryToken ( )
{
  assert ( IsValid ( ) );

  HANDLE hToken = 0;
  SECURITY_STATUS status = 0;
  status = g_sspi->QuerySecurityContextToken (
                &m_hCtxt,
                &hToken
              );
  if ( status != SEC_E_OK )
    throwexe ( err_query_token_failed, status );
  return hToken;
}

// == authentication ==
/**
  This is the core functionality of SSPI:
  Authentication. With this, you make the
  server and client talk to one another to establish
  a security context.
*/
auth_state Context::Authenticate ( Buffer * in, Buffer * out )
{
  assert ( out != 0 );
  assert ( m_cred != 0 );
  assert ( m_cred->IsValid ( ) );
  out->Free ( );

  BufferDesc ibd, obd;

  if ( in != 0 )
    ibd.add ( in );
  obd.add ( out );
  out->Allocate ( m_cred->Package().MaxTokenSize ( ), bt_token );

  SECURITY_STATUS status = 0;
  status = CreateContext ( 
                m_have_ctxt ? &m_hCtxt : NULL,
                (in != 0 ) ? ibd.get_bd ( ) : NULL,
                &m_hCtxt,
                obd.get_bd ( )
              );
  if ( (status == SEC_I_COMPLETE_NEEDED) ||
       (status == SEC_I_COMPLETE_AND_CONTINUE) )
  {
    if ( g_sspi->CompleteAuthToken != NULL )
      g_sspi->CompleteAuthToken ( &m_hCtxt, obd.get_bd ( ) );
  }
  
  switch ( status )
  {
  case SEC_E_OK:
  case SEC_I_COMPLETE_NEEDED:
    m_state = as_ok;   // we're done here
    break;
  case SEC_I_CONTINUE_NEEDED:
  case SEC_I_COMPLETE_AND_CONTINUE:
    m_state = as_continue;  // keep on going
    break;
  case SEC_E_LOGON_DENIED:
    m_state = as_denied;    // logon denied
    break;
  default:
    m_state = as_error;
    throwexe ( err_auth_failed, status );
  }
  // we now have a security context
  m_have_ctxt = true;
  obd.update ( );
  return m_state;
}


//======================================================================
// ServerContext implementation


SECURITY_STATUS 
ServerContext::CreateContext ( 
            PCtxtHandle old_ctxt, PSecBufferDesc ibd,
            PCtxtHandle new_ctxt, PSecBufferDesc obd
          )
{
  assert ( ibd != 0 );

  DWORD     ctxt_attr;
  TimeStamp expiration;

  SECURITY_STATUS status = 0;
  status = g_sspi->AcceptSecurityContext (
                m_cred->GetHandle ( ),
                old_ctxt,
                ibd,
                m_ctxt_reqs & ~ASC_REQ_ALLOCATE_MEMORY,
                m_data_rep, new_ctxt,
                obd,
                &ctxt_attr, &expiration
              );
  return status;
}

/**
  Call this once you are done with Context::Authenticate()
  Sending the client the buffer returned by this call,
  you ensure that the client knows the real result of
  the authentication process (e.g. logon denied, etc).

  The returned buffer is allocated by the function, and
  freed automatically on the buffer's destruction.
*/
void ServerContext::ConfirmAuthentication ( Buffer & buf )
{
  // here we build the confirmation 
  // message to the client that confirms the
  // login
  buf.Free ( );
  buf.Allocate ( sizeof(auth_state), bt_confirmation );
  buf.SetContents ( (BYTE*)&m_state, sizeof(m_state) );
} 

/**
  Causes the current thread to start impersonating
  the current security context.
*/
void ServerContext::ImpersonateClient ( )
{
  assert ( IsValid ( ) );
  assert ( m_state == as_ok );
  SECURITY_STATUS status = 0;
  status = g_sspi->ImpersonateSecurityContext ( GetHandle ( ) );

  if ( status != SEC_E_OK )
    throwexe ( err_impersonate, status );
}

/**
  Reverts the impersonation settings so that the thread
  returns to it's original security context.
*/
void ServerContext::RevertToSelf ( )
{
  assert ( IsValid ( ) );
  assert ( m_state == as_ok );
  SECURITY_STATUS status = 0;
  status = g_sspi->RevertSecurityContext ( GetHandle ( ) );

  if ( status != SEC_E_OK )
    throwexe ( err_revert_to_self, status );
}


//======================================================================
// ServerContext implementation

SECURITY_STATUS 
ClientContext::CreateContext ( 
            PCtxtHandle old_ctxt, PSecBufferDesc ibd,
            PCtxtHandle new_ctxt, PSecBufferDesc obd
          )
{
  DWORD     ctxt_attr;
  TimeStamp expiration;

  // check the input buffer and see if it's a confirmation
  if ( ibd != 0 && ibd->pBuffers[0].BufferType == bt_confirmation )
  {
    m_state = *((auth_state*)ibd->pBuffers[0].pvBuffer);
    if ( m_state != as_ok ) return SEC_E_LOGON_DENIED;
    else return SEC_E_OK;
  }

  SECURITY_STATUS status = 0;
  status = g_sspi->InitializeSecurityContext (
                m_cred->GetHandle ( ),
                old_ctxt,
                const_cast<TCHAR*>(m_cred->Target()),
                m_ctxt_reqs & ~ISC_REQ_ALLOCATE_MEMORY,
                0, m_data_rep,
                ibd, 0, new_ctxt, obd,
                &ctxt_attr, &expiration
              );
  // whatever the return, wait for the server to 
  // confirm authentication
  if ( status == SEC_E_OK )
    status = SEC_I_CONTINUE_NEEDED; 
  else if ( status == SEC_I_COMPLETE_NEEDED )     
    status = SEC_I_COMPLETE_AND_CONTINUE;
  return status;
}
