/*
 * Copyright (c) 2014-2015 Jesse Sipprell <jessesipprell@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 */

// This package implements a syncronization algorithm intended for use cases
// where access to shared data is required by numerous concurrent goroutines
// at once in read-only mode with intermittent safe write access required
// (such as updating from snapshots). During write access all readers block
// and are released once the write has completed.
//
// 1. During normal read-only opertation multiple goroutines may
//    hold a "lock" on the barricade (not really a lock, no
//    mutexes are used until a write lock is required).
//
// 2. When write access is necessary, one (at a time) goroutine calls
//    WLock(). This will cause the pending writer to wait until all
//    reading goroutines have released. Any attempts to acquire new
//    RLock()s during this period will queue up pending write completion.
//
// 3. Once all prior RLock()s are complete, the WLock() is accepted and
//    returns to the caller. Until WUnlock() is called any new RLock()s
//    are queued and block.
//
// 4. When WUnlock() is called any queued goroutines blocked on a pending
//    RLock() are released and the barricade drops back into "mutexless"
//    mode unless the next write is requested.
package barricade

import (
	"sync"
	"sync/atomic"
)

type BarricadeUnlocker interface {
	RUnlock()
}

// RLock() and RLockTry() both attempt to return a interface that
// has a single RUnlock() method that should be released using
// the following pattern:
//
//     locked := b.RLock()
//     defer locked.RUnlock()
//
// RLockTry() never blocks but returns nil if a read-lock is not
// immediately available:
//
//     if locked := b.RLockTry(); locked != nil {
//       defer locked.RUnlock()
//       ...
//     }
type BarricadeLocker interface {
	RLock() BarricadeUnlocker
	RLockTry() BarricadeUnlocker
}

type Barricade interface {
	BarricadeLocker
	WLock()
	WUnlock()
}

type bLock struct {
	enabled         uint32
	c               *sync.Cond
	pending         chan int
	npendingReaders uint32
}

type barricade struct {
	lock *bLock
	c    chan *bLock
	wsem chan struct{}
}

type bUnlockFunc func()

func (fn bUnlockFunc) RUnlock() {
	fn()
}

func (b *bLock) runlock(c chan<- *bLock) {
	c <- b
	if atomic.LoadUint32(&b.enabled) > 0 {
		b.c.L.Lock()
		defer b.c.L.Unlock()
		if atomic.LoadUint32(&b.enabled) == 0 {
			return
		}
		select {
		case b.pending <- int(atomic.LoadUint32(&b.npendingReaders)):
		default:
			panic("pending channel overflow (Unlock)")
		}
	}
}

func (b *bLock) rlock(blocking bool) bool {
	if atomic.LoadUint32(&b.enabled) > 0 {
		b.c.L.Lock()
		defer b.c.L.Unlock()
		if atomic.LoadUint32(&b.enabled) == 0 {
			return true
		}
		if !blocking {
			return false
		}
		select {
		case b.pending <- int(atomic.AddUint32(&b.npendingReaders, uint32(1))):
		default:
			panic("pending channel overflow (Lock)")
		}
		defer atomic.AddUint32(&b.npendingReaders, ^uint32(0))
		for atomic.LoadUint32(&b.enabled) > 0 {
			b.c.Wait()
		}
	}

	return true
}

// Return a new Barricade initialized to support up to `maxConcurrency` concurrent readers.
// Attemps to RLock() or RLockTry() once `maxConcurrency` read-locks have been acquired
// will block or return nil respectively.
//
// NB: only one goroutine may acquire the write-lock at once via WLock().
func New(maxConcurrency int) Barricade {
	b := &barricade{
		lock: &bLock{
			c:       &sync.Cond{L: &sync.Mutex{}},
			pending: make(chan int, maxConcurrency),
		},
		c:    make(chan *bLock, maxConcurrency),
		wsem: make(chan struct{}, 1),
	}

	b.wsem <- struct{}{}
	for {
		select {
		case b.c <- b.lock:
		default:
			return b
		}
	}
}

// Identical to RLock() but returns nil if no read-lock is currently available for any reason.
// NB: never blocks.
func (b *barricade) RLockTry() (unl BarricadeUnlocker) {
	select {
	case bl := <-b.c:
		if bl.rlock(false) {
			unl = bUnlockFunc(func() { bl.runlock(b.c) })
		} else {
			b.c <- bl
		}
	default:
	}
	return
}

func (b *barricade) RLock() BarricadeUnlocker {
	bl := <-b.c
	defer bl.rlock(true)
	return bUnlockFunc(func() { bl.runlock(b.c) })
}

func (b *barricade) wlockCheck() (int, int) {
	b.lock.c.L.Lock()
	defer b.lock.c.L.Unlock()

	return cap(b.c), len(b.c)
}

func (b *barricade) wlockWait(pend <-chan int) {
	c, l := cap(b.c), len(b.c)
	b.lock.c.L.Unlock()
	defer b.lock.c.L.Lock()

	for c > l {
		select {
		case i := <-pend:
			c, l = b.wlockCheck()
			if i == c-l {
				return
			}
		}
	}
}

// Acquire a write-safe lock. Only one goroutine may hold a write-lock per
// barricade. This call will block if there are any readers currently operating
// with read-locks, however all new readers will themselves block until this
// call returns *and* WUnlock() is called.
func (b *barricade) WLock() {
	<-b.wsem
	defer func() {
		if e := recover(); e != nil {
			b.wsem <- struct{}{}
			panic(e)
		}
	}()
	b.lock.c.L.Lock()
	defer b.lock.c.L.Unlock()

	b.drainPending()
	if atomic.AddUint32(&b.lock.enabled, uint32(1)) != uint32(1) {
		panic("corrupted state")
	}
	b.wlockWait(b.lock.pending)
}

func (b *barricade) drainPending() {
	for {
		select {
		case <-b.lock.pending:
		default:
			return
		}
	}
}

// Release a previously acquired write-lock (via WLock()).
// This will have the side effect of awaking any pending goroutines
// which are waiting on read-locks.
//
// NB: it is an error to call WUnlock() without a matching prior WLock().
func (b *barricade) WUnlock() {
	defer func() {
		if e := recover(); e == nil {
			b.wsem <- struct{}{}
		} else {
			panic(e)
		}
	}()
	b.lock.c.L.Lock()
	defer b.drainPending()
	defer b.lock.c.L.Unlock()

	if atomic.LoadUint32(&b.lock.npendingReaders) > 0 {
		defer b.lock.c.Broadcast()
	}
	atomic.CompareAndSwapUint32(&b.lock.enabled, uint32(1), uint32(0))
}
