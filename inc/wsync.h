
//
// wsync.h: a set of C++ classes and templates that make using Win32
//          syncronization objects easier
//
// Contents:    
//              * CriticalSection - a CRITICAL_SECTION wrapper
//              * Event           - an EVENT wrapper
//              * Mutex           - a MUTEX wrapper
//              * Semaphore       - a SEMAPHORE wrapper
//              * QueueSemaphore  - a H-P semaphore for queues
//              * SyncLock        - template for using the objects
//
//              The QueueSemaphore class was inspired by a post from
//		          Stefan Gustafsson in microsoft.public.win32.programmer.kernel
//
// Revisions: 	10/26/1999 - created 
//              12/31/1999 - Added Semaphore and QueueSemaphore
//              01/01/2000 - Added Mutex
//              02/25/2001 - fixed namespaces
//
// This file is part of the Winterdom library
// Copyright (C) 2000-2001, Tomas Restrepo (tomasr@mvps.org)
//            
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#ifndef WSYNC_H__INCLUDED
#define WSYNC_H__INCLUDED

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "wctypes.h"


//
// All classes are in namespace
// Tomasr::Runtime::Threading
//
namespace Winterdom { 
   namespace Runtime {
      namespace Threading {

   // CLASS SIGNATURE
   // all syncronization wrapper objects should have this
   // layout so that SyncLock can use them. We don't 
   // use inheritance to keep the classes lightweight
   // class SyncObject 
   // {
   //  public:
   //      void Acquire ( );
   //      void Release ( );
   // }
   //

   //
   // CRITICAL_SECTION wrapper class
   //
   class CriticalSection
   {
   public:
      CriticalSection ( ) 
      { 
         InitializeCriticalSection ( &m_CritSec ); 
      }
      ~CriticalSection ( ) 
      { 
         DeleteCriticalSection ( &m_CritSec );
      }
      void Acquire ( ) 
      { 
         EnterCriticalSection ( &m_CritSec ); 
      }
      void Release ( ) 
      { 
         LeaveCriticalSection ( &m_CritSec ); 
      }
   private:
      CriticalSection ( const CriticalSection& c );
      CriticalSection& operator= ( const CriticalSection& c );
      CRITICAL_SECTION m_CritSec;
   };

   //
   // Event wrapper class
   //
   class Event
   {
   public:
      Event ( ) 
         : m_hEvent ( NULL ) 
      { 
      }
      ~Event ( ) 
      { 
         if ( m_hEvent != NULL )
            CloseHandle ( m_hEvent ); 
      }
      bool Create ( BOOL IsManualReset = TRUE, BOOL InitialState = FALSE,
                    LPCTSTR Name = NULL ) 
      {  
         m_hEvent = CreateEvent ( NULL, IsManualReset, InitialState, Name );
         return (m_hEvent != NULL);
      }
      void Acquire() 
      { 
         WaitForSingleObject ( m_hEvent, INFINITE ); 
      }
      void Release()
      { 
         SetEvent ( m_hEvent );
      }
      void Pulse()
      { 
         PulseEvent ( m_hEvent );
      }
      void Reset()
      {
         ResetEvent ( m_hEvent );
      }
      HANDLE Handle ( ) 
      { 
         return m_hEvent; 
      }
   private:
      HANDLE m_hEvent;
   };

   //
   // Mutex wrapper class
   //
   class Mutex
   {
   public:
      Mutex ( ) 
         : m_hMutex(NULL), m_AlreadyExists(false) 
      { 
      }
      ~Mutex ( ) 
      { 
         if ( m_hMutex != NULL )
            CloseHandle ( m_hMutex ); 
      }
      bool Create ( BOOL GetOwnership = FALSE, 
                    LPCTSTR Name = NULL ) 
      {  
         m_hMutex = CreateMutex ( NULL, GetOwnership, Name );
         if ( GetLastError() == ERROR_ALREADY_EXISTS )
            m_AlreadyExists = true;
         return (m_hMutex != NULL);
      }
      void Acquire ( ) 
      { 
         WaitForSingleObject ( m_hMutex, INFINITE ); 
      }
      void Release ( )
      { 
         ReleaseMutex ( m_hMutex );
      }
      HANDLE Handle ( ) 
      { 
         return m_hMutex; 
      }
      // did the object already exist when we opened it?
      bool AlreadyExists() const 
      {
         return m_AlreadyExists;
      }
   private:
      HANDLE m_hMutex;
      bool m_AlreadyExists;
   };

   // 
   // this is your basic semaphore
   // not suitable for queues, because the wait
   // is too long at the begining
   //
   class Semaphore
   {
   public:
      Semaphore ( ) 
         : m_hSemaphore ( NULL )
      { 
      }
      ~Semaphore ( ) 
      { 
         if ( m_hSemaphore != NULL )
            CloseHandle ( m_hSemaphore ); 
      }
      bool Create ( long    InitialCount, 
                    long    MaxCount, 
                    LPCTSTR Name = NULL ) 
      {
         m_hSemaphore = CreateSemaphore ( NULL, InitialCount, MaxCount, Name );
         return (m_hSemaphore != NULL);
      }
      void Acquire ( ) 
      {
         WaitForSingleObject ( m_hSemaphore, INFINITE );
      }
      void Release ( )
      {
         ReleaseSemaphore ( m_hSemaphore, 1, NULL );
      }
      HANDLE Handle ( ) 
      { 
         return m_hSemaphore; 
      }
   private:
      HANDLE m_hSemaphore;
   };


   //
   // This is a much faster semaphore for use in 
   // high-performance queues, since it lets the 
   // queue fill up very quickly.
   // Performance increases because we don't block
   // threads if we haven't reached MaxCount Acquisitions
   // of the Semaphore. The semaphore itself allows us
   // to block threads once we've reached MaxCount
   //
   class QueueSemaphore
   {
   public:
      QueueSemaphore ( ) 
         : m_hSemaphore(NULL), m_Count(0)
      { 
      }
      ~QueueSemaphore ( ) 
      { 
         if ( m_hSemaphore != NULL )
            CloseHandle ( m_hSemaphore ); 
      }
      bool Create ( long MaxCount ) 
      {
         m_Count = MaxCount;
         m_hSemaphore = CreateSemaphore ( NULL, 0, 0x7FFFFFFF, NULL );
         return (m_hSemaphore != NULL);
      }
      void Acquire ( ) 
      {
         if ( ::InterlockedDecrement ( &m_Count ) < 0 )
         {
            WaitForSingleObject ( m_hSemaphore, INFINITE );
            //
            // In some contexts, we'll want to sleep to
            // avoid the priority boost the system gives the 
            // current thread after the wait
            //
#ifdef WQS_ACQUIRESLEEP
            Sleep ( 0 );
#endif
         }
      }
      void Release ( )
      {
         if ( ::InterlockedIncrement ( &m_Count ) <= 0 )
            ReleaseSemaphore ( m_hSemaphore, 1, NULL );
      }
      HANDLE Handle ( ) 
      { 
         return m_hSemaphore; 
      }
   private:
      HANDLE m_hSemaphore;
      long   m_Count;
   };

   template <class T>
   class SyncLock
   {
   public:
      SyncLock ( T& obj ) 
         : m_SyncObject ( obj )
      { 
         m_SyncObject.Acquire ( );
      }

      ~SyncLock()
      {
         m_SyncObject.Release ( );
      }

   private:
      T&  m_SyncObject;
   };

   // common typedefs
   typedef SyncLock<CriticalSection> CriticalSectionLock;
   typedef SyncLock<Event> EventLock;
   typedef SyncLock<Semaphore> SemaphoreLock;

      } // namespace Threading
   } // namespace Runtime
} // namespace Winterdom

#endif // WSYNC_H__INCLUDED
