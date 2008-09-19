//==============================================================================
// File: 			    sspibuf.h
//
// Description: 	declaration of our buffer management classes
//
// Revisions: 		8/7/2000 - created
//
//==============================================================================
// Copyright(C) 2000, Tomas Restrepo. All rights reserved
// Send comments to: tomasr@mvps.org
//==============================================================================

#ifndef SSPIBUF_H__INCLUDED
#define SSPIBUF_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000



/**
  who owns the buffer?
  we need to know how to free it
*/
enum buffer_owner {
  bo_sspi     =0,   // use FreeContextBuffer() to release
  bo_user     =1,   // owned by the user, he frees it
  bo_lib      =2,   // owned by wsspi, we release it
};

/**
  what's the buffer type?
  (another name for the SECBUFFER_ constants)
*/
enum buffer_type {
  bt_empty            = SECBUFFER_EMPTY,
  bt_data             = SECBUFFER_DATA,
  bt_token            = SECBUFFER_TOKEN,
  bt_pkg_params       = SECBUFFER_PKG_PARAMS,
  bt_missing          = SECBUFFER_MISSING,
  bt_extra            = SECBUFFER_EXTRA,
  bt_stream_trailer   = SECBUFFER_STREAM_TRAILER,
  bt_stream_header    = SECBUFFER_STREAM_HEADER,
  bt_negotiation_info = SECBUFFER_NEGOTIATION_INFO,
  bt_padding          = SECBUFFER_PADDING,
  bt_stream           = SECBUFFER_STREAM,
  bt_mechlist         = SECBUFFER_MECHLIST,  
  bt_ml_signature     = SECBUFFER_MECHLIST_SIGNATURE,  

  bt_confirmation     = 99,  // our own message to signal the client
};

/**
  Buffer represents a communication
  unit between server and client.

  Buffer esencially wraps the SecBuffer structure,
  with added benefits. The most important one is that
  it can deal with 3 types of buffers:
  <ul>
  <li> library owned buffers: Allocated internally by the
    wsspi for you, via the Allocate() method. Buffer
    will free these for you.
  <li> SSPI owned buffers: Such as those returned by
    Context::Export(). Buffer will call 
    FreeContextBuffer() for you.
  <li> User owned buffers: such as when you have the data
    already in your own buffer. Buffer will never free
    these buffers, but it can change it's internal pointer
    to reference other memory, so hold your own copy of the pointer
    if you need to free your buffer later.
  </ul>
*/
class no_vtable Buffer : private SspiBase
{
public:
  Buffer ( );
  ~Buffer ( );

  // == copy ctor/assignment ==
  Buffer ( const Buffer & buf );
  Buffer & operator= ( const Buffer & buf );

  // == serialization support ==
  void FromByteStream ( const BYTE * stream, DWORD size, buffer_type type );
  const BYTE * ByteStream ( ) const;
  // == allocation, the buffer is ours ==
  void Allocate ( DWORD size, buffer_type type );
  BYTE * GetBufferForRecv ( );
  void SetContents ( const BYTE * stream, DWORD size );

  // == accessors ==
  bool IsValid ( ) const;
  DWORD Size ( ) const;
  void SetSize ( DWORD size );
  buffer_type Type ( ) const;
  void SetType ( buffer_type type );
  buffer_owner Owner ( ) const;
  void SetOwner ( buffer_owner owner );
  PSecBuffer GetSecBuffer ( );
  void Free ( );

private:
  //! who owns the buffer memory?
  buffer_owner  m_owner;   
  //! internal SecBuffer struct
  SecBuffer     m_buffer;
}; // Classs Buffer



/**
  This class is a buffer descriptor
  that wraps the SecBufferDesc structure. 
  It's lightweight and makes it very easy to 
  add/remove/query buffers.
 
  IMPORTANT: BufferDesc is a container with
  REFERENCE semantics, thus, it's *your*
  responsability to free the buffers.
  However,this is taken care of by scope rules
  if used correctly.

  The disadvantage is that iterators will act
  like Buffer**, which means you need two
  indirections to actually get at the data using
  them. I plan on writing my own iteration classes for
  this but I'm too lazy right now!
*/
class BufferDesc
{
private:
  typedef std::vector<Buffer*> bdvector;
public:
  typedef bdvector::iterator       iterator;
  typedef bdvector::const_iterator const_iterator;

  BufferDesc ( );
  ~BufferDesc( );
  // == public interface == 
  void add ( Buffer * buf, size_t n = 1 );
  iterator erase ( iterator it );
  iterator begin ( );
  const_iterator begin ( ) const;
  iterator end ( );
  const_iterator end ( ) const;
  Buffer * operator[] ( unsigned index );
  const Buffer * operator[] ( unsigned index ) const;
  size_t size ( ) const;

  // == buffer context management ==
  SecBufferDesc * get_bd ( );
  void update ( );
  
private:
  void free ( );

private:
  //! internal SecBufferDesc struct
  SecBufferDesc m_desc;
  //! internal list of Buffers
  bdvector      m_list;
}; // class BufferDesc

#endif // SSPIBUF_H__INCLUDED
