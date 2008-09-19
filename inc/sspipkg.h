//==============================================================================
// File: 			    sspipkg.h
//
// Description: 	declaration of our package support classes
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPIPKG_H__INCLUDED
#define SSPIPKG_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

// forward declaration 
class Credentials;

/**
  SecPkg represents a security package, 
  as a lightweight wrapper around the
  SecPkgInfo structure
*/
class no_vtable SecPkg : private SspiBase
{
public:
  SecPkg ( const TCHAR * pkgname = NULL );
  SecPkg ( const SecPkgInfo * pkg );
  ~SecPkg ( );
  // == copy contruction/assignment ==
  SecPkg ( const SecPkg & pkg );
  SecPkg & operator= ( const SecPkg & pkg );

  // == accessors ==
  bool HasCapabilities ( ULONG caps ) const;
  USHORT Version ( ) const;
  USHORT RpcId ( ) const;
  ULONG MaxTokenSize ( ) const;
  wsstring Name ( ) const;
  wsstring Comment ( ) const;
  bool IsValid ( ) const;
  // == operators ==
  int operator== ( const SecPkg & pkg ) const;
  int operator== ( const wsstring & pkgname ) const;
  int operator!= ( const SecPkg & pkg ) const;
  int operator!= ( const wsstring & pkgname ) const;

  friend Credentials;

private:
  bool GetLocalCopy ( const SecPkgInfo * pkg );
  void Free ( );

private:
  //! do we hold a valid package?
  bool        m_have_pkg;
  //! package information
  SecPkgInfo  m_info;
}; // class SecPkg

// == dumper ==
wsostream & operator<< ( wsostream & o, const SecPkg & p );


/**
  PkgList holds the list of all 
  security packages installed of the system. 
  It's purpose is to allow easy enumeration at
  runtime.
  
  It esencially behaves like a read-only std::vector
  object.
*/
class PkgList : private std::vector<SecPkg>
{
private:
  typedef std::vector<SecPkg> plvector;
public:
  using plvector::iterator;
  using plvector::const_iterator;
  using plvector::begin;
  using plvector::end;
  using plvector::size;

  PkgList ( );
}; // class PkgList

#endif // SSPIPKG_H__INCLUDED
