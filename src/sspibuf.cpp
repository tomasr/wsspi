//==============================================================================
// File: 			    sspibuf.cpp
//
// Description: 	implementation of our buffer management classes
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
// Buffer implementation

Buffer::Buffer ( )
  : m_owner ( bo_user )
{
  m_buffer.cbBuffer   = 0;
  m_buffer.BufferType = 0;
  m_buffer.pvBuffer   = 0;
}
Buffer::~Buffer ( )
{
  Free ( );
}

// == copy ctor/assignment ==
Buffer::Buffer ( const Buffer & buf )
{
  m_owner = bo_lib;
  m_buffer.cbBuffer   = buf.Size ( );
  m_buffer.BufferType = buf.Type ( );
  m_buffer.pvBuffer   = new BYTE[buf.Size ( )];
  if ( m_buffer.pvBuffer == 0 )
    throwex ( err_no_memory );
  memcpy ( m_buffer.pvBuffer, buf.ByteStream ( ), buf.Size ( ) );
}

Buffer & Buffer::operator= ( const Buffer & buf )
{
  if ( &buf != this )
  {
    m_owner = bo_lib;
    m_buffer.cbBuffer   = buf.Size ( );
    m_buffer.BufferType = buf.Type ( );
    m_buffer.pvBuffer   = new BYTE[buf.Size ( )];
    if ( m_buffer.pvBuffer == 0 )
      throwex ( err_no_memory );
    memcpy ( m_buffer.pvBuffer, buf.ByteStream ( ), buf.Size ( ) );
  }
  return *this;
}

// == serialization support ==
/**
  Assigns the referenced stream to this instance
  of Buffer. Its type will be bo_user.
  
  If the Buffer held data previously, it 
  will be released.
*/
void Buffer::FromByteStream ( const BYTE * stream, DWORD size, buffer_type type )
{
  // release previous stream
  Free ( );
  m_owner = bo_user;
  m_buffer.cbBuffer   = size;
  m_buffer.BufferType = type;
  m_buffer.pvBuffer   = (void*)stream;
}
/**
  Returns a const pointer to the internal data stream
  you can use to, say, send the buffer to a remote site.
*/
const BYTE * Buffer::ByteStream ( ) const
{ 
  assert ( IsValid ( ) );
  return (BYTE*)m_buffer.pvBuffer; 
}

// == allocation, the buffer is ours ==
/**
  Allocates memory in this Buffer instance
  of a given size, and with a given buffer type.

  If the Buffer held data previously, it 
  will be freed.
*/
void Buffer::Allocate ( DWORD size, buffer_type type )
{ 
  Free ( );
  m_buffer.pvBuffer = (void*) new BYTE[size];
  if ( m_buffer.pvBuffer == 0 )
    throwex ( err_no_memory );
  SetSize ( size );
  SetOwner ( bo_lib );
  SetType ( type );
}
/**
  Get a non-const pointer to the internal data stream.
  I generally dislike returning non-const pointers to
  internal buffers, but this one is very useful. 
  For example, if you are receiving a buffer from the network
  you can recv() the buffer size, use Buffer::Allocate() to 
  get memory, and then pass the pointer returned by 
  GetBufferForRecv() to recv() to get the real data stream.

  Be carefull never to free the pointer, though.
*/
BYTE * Buffer::GetBufferForRecv ( ) 
{
  assert ( IsValid ( ) );
  return (BYTE*)m_buffer.pvBuffer;
}
/**
  Copy the memory pointed to by stream into this instance's
  internal buffer. size must be less or equal to the
  allocated memory.
*/
void Buffer::SetContents ( const BYTE * stream, DWORD size )
{
  assert ( IsValid ( ) );
  assert ( size <= m_buffer.cbBuffer );
  memcpy ( m_buffer.pvBuffer, stream, size );
}

/**
  Is this a valid buffer?
  A Buffer instance is valid if it has allocated memory
  and it's size is larger than 0.

  This is specially useful to determine
  if the buffer should be sent or not.
*/
bool Buffer::IsValid ( ) const
{
  return ((m_buffer.cbBuffer != 0 && m_buffer.pvBuffer != 0)); 
}

// == accessors ==
/**
  Returns the buffer size.
*/
DWORD Buffer::Size ( ) const
{
  return m_buffer.cbBuffer; 
}
/**
  Set's the buffer size.
  Notice this doesn't actually cause a 
  memory reallocation, just changes the 
  size member. 
*/
void Buffer::SetSize ( DWORD size ) 
{
  m_buffer.cbBuffer = size;
}

/**
  Return the buffer type.
  Notice that buffer_type is simply an enum mapping the 
  SECBUFFER_ constants, plus some wsspi-specific types.
*/
buffer_type Buffer::Type ( ) const
{
  return (buffer_type)(m_buffer.BufferType); 
}
/**
  Changes this Buffer's type.
*/
void Buffer::SetType ( buffer_type type )
{
  m_buffer.BufferType = type; 
}

/**
  Return the buffer's owner.
*/
buffer_owner Buffer::Owner ( ) const
{
  return m_owner; 
}
/**
  Sets the buffer owner. 
  This is used internally by the library, and you should not
  have to call it yourself, as it could be dangerous.
*/
void Buffer::SetOwner ( buffer_owner owner )
{
  m_owner = owner;  
}

/**
  Returns a pointer to the internal SecBuffer struct.
  Used by the library internally.
*/
PSecBuffer Buffer::GetSecBuffer ( )
{
  return &m_buffer;
}

/**
  Releases internal data, according to who owns the buffer.
*/
void Buffer::Free ( )
{
  if ( m_buffer.pvBuffer == 0 )
    return;
  switch ( m_owner )
  {
  case bo_sspi: 
    g_sspi->FreeContextBuffer ( m_buffer.pvBuffer );
    break;
  case bo_user: 
    break;  // don't do anything
  case bo_lib:  
    delete [] m_buffer.pvBuffer; 
    break;
  }
  m_buffer.pvBuffer = 0;
  m_buffer.cbBuffer = 0;
  m_buffer.BufferType = bt_empty;
}


//==============================================================================
// BufferDesc implementation

BufferDesc::BufferDesc ( )
{
  m_desc.cBuffers  = 0;
  m_desc.ulVersion = SECBUFFER_VERSION;
  m_desc.pBuffers  = 0;
}
BufferDesc::~BufferDesc( )
{
  free ( );
  m_list.erase ( m_list.begin(), m_list.end() );
}

// == public interface == 
/**
  Adds one or more buffers to the descriptor
*/
void BufferDesc::add ( Buffer * buf, size_t n /* = 1 */ )
{
  assert ( buf != 0 );
  assert ( n >= 1 );
  for ( size_t i = 0; i < n; i++ )
    m_list.push_back ( &buf[i] );
}

/**
  Removes the specified buffer from the descriptor
*/
BufferDesc::iterator BufferDesc::erase ( iterator it )
{
  return m_list.erase ( it );
}

/**
  Returns the first buffer in the descriptor
*/
BufferDesc::iterator BufferDesc::begin ( )
{
  return m_list.begin ( );
}
BufferDesc::const_iterator BufferDesc::begin ( ) const
{
  return m_list.begin ( );
}

/**
  Returns an iterator pointing past the end
  of the buffer list in the descriptor
*/
BufferDesc::iterator BufferDesc::end ( )
{
  return m_list.end ( );
}
BufferDesc::const_iterator BufferDesc::end ( ) const
{
  return m_list.end ( );
}

/**
  Returns a pointer to the specified buffer in
  the descriptor
*/
Buffer * BufferDesc::operator[] ( unsigned index ) 
{
  return m_list[index];
}
const Buffer * BufferDesc::operator[] ( unsigned index ) const
{
  return m_list[index];
}

/**
  Returns the number of buffers in the descriptor
*/
size_t BufferDesc::size ( ) const
{
  return m_list.size ( );
}

// == buffer context management ==
/**
  Returns a pointer to the internal SecBufferDesc
  structure wrapped by this BufferDesc instance.
  This is used by the library, so you should not need
  to call it yourself.

  The SecBufferDesc returns contains a pointer to  
  temporary memory, which should be freed. Once you are done
  with the SecBufferDesc, call BufferDesc::update()
  to release the temporary memory and make sure all changes
  to the descriptor are replicated on it's buffers.
*/
SecBufferDesc * BufferDesc::get_bd ( )
{
  // allocate the array and fill it.
  // it's only valid until the next 
  // function call
  free ( );
  m_desc.cBuffers = size ( );
  m_desc.pBuffers = new SecBuffer[m_desc.cBuffers];
  if ( m_desc.pBuffers == 0 )
    throwex ( err_no_memory );

  ULONG i = 0;
  for ( iterator it = begin(); it != end(); it++, i++ )
  {
    SecBuffer * buf = ((*it)->GetSecBuffer());
     m_desc.pBuffers[i] = *buf;
  }
  return &m_desc;    
}
/**
  Releases temporary memory allocated by 
  BufferDesc::get_bd() and replicates changes to it 
  into the Buffers we hold.
*/
void BufferDesc::update ( )
{
  ULONG i = 0;
  for ( iterator it = begin(); it != end(); it++, i++ )
  {
     (*it)->SetSize ( m_desc.pBuffers[i].cbBuffer );
     (*it)->SetType ( (buffer_type)m_desc.pBuffers[i].BufferType );
  }
  free ( );    
}

/**
  Releases internal data
*/
void BufferDesc::free ( )
{
  if ( m_desc.pBuffers != 0 )
    delete [] m_desc.pBuffers;
  m_desc.pBuffers = 0;
}

