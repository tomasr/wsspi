//==============================================================================
// File: 			    sspilib.h
//
// Description: 	declaration of our library object
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPILIB_H__INCLUDED
#define SSPILIB_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/**
  \mainpage
  WSSPI is a library I built to simplify the use of the SSPI 
  <i>(Security Support Provider Interface)</i> for various purposes.

  This second [pre-release] version of the library adds a lot
  of functionality, including:
  <ul>
    <li> Wraps the full SSPI api including encryption/decryption and
    message signing.
    <li> Adds better support for buffer management, including buffer
    descriptors and multiple buffer-owners.
    <li> Adds automatic confirmation of the authentication process to
    the client.
  </ul>

  The Initial release of the library was severely limited in functionality.
  This second version was designed with two things in mind:
  <ol>
    <li> Flexibility: I wanted to make the library really flexible. You can
    easily extend parts of the library, or choose your own flags. This allows you
    to easily specify, for example, which credential use you want to have. Also, 
    Also, many of the public interfaces are built with simplicity and 
    type-safety in mind.

    <li> Extensibility: You can very easily ad support for new providers (packages).
    For example, if you don't need special functionality out of them, there's a
    SimpleCredentials class which can be used with any provider. Also, we have
    built-in support for NTLM and Kerberos, and soon for schannel. Adding support for
    a new provider is as simple as deriving your own class from the Credentials class
    and adding your own wrapper call to AcquireCredentialsHandle().
  </ol>

  I'd love to hear if you are using this library in any of your projects, or if you
  just found it useful in learning about SSPI.

  \author Tomas Restrepo \<tomasr@mvps.org\>
  \author see http://www.mvps.org/windev/security/wsspi.html
*/

/**
  class library wrapper. 
  SspiLib is responsible for loading the provider dll 
  and retrieving the function pointer table. 

  To simplify the library creation, we use a thread-safe 
  singleton implementation.
  This is what forces us to use a .lib!

  For simplicity, the lib object is ref-counted. If the class
  is not derived from SspiBase, you should make sure you call 
  SspiLib::Release() when you are done with it.
*/
class no_vtable SspiLib
{
public:
  SspiLib ( );
  ~SspiLib ( );

  void AddRef ( );
  void Release ( );
  PSecurityFunctionTable operator-> ( );
  //! singleton creation
  static SspiLib & Instance ( );

private:
  //! provider dll module handle
  HMODULE m_hModule;
  //! pointer to function table
  PSecurityFunctionTable m_fpt;
  //! reference count
  long m_refcount;

  //! singleton lock
  static Winterdom::Runtime::Threading::CriticalSection m_lock;
  //! singleton instance
  static SspiLib * m_instance;
}; // class SspiLib

/**
  SspiBase is the clas we derive all of our
  classes that make use of the SSPI api.
  This is for convient use of the singleton
*/
class no_vtable SspiBase
{
public:
  SspiBase ( )
    : g_sspi (SspiLib::Instance ( ))
  {
  }
  ~SspiBase ( )
  {
    g_sspi.Release ( );
  }
protected:
  //! library reference
  SspiLib & g_sspi;
}; // class SspiBase

#endif // SSPILIB_H__INCLUDED
