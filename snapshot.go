package main

import (
	"log"
	"time"

	"golang.org/x/net/context"
)

const (
	_                = iota
	snapOpAdd snapOp = iota
	snapOpDel
)

const defaultSnapshotFlushInterval = time.Duration(100) * time.Millisecond

type snapOp int

type snapReqUpd struct {
	gate   chan error
	updSet []Matcher
}

type snapReqFlush struct {
	resetExpireTimer bool
	gate             chan error
}

type snapOperation struct {
	op snapOp
	v  interface{}
}

type snapshot struct {
	*RRCacheView

	Cache *RRCache

	reqUpdCh   chan snapReqUpd
	reqFlushCh chan snapReqFlush
	snapset    []snapOperation
}

func (s *snapshot) addToSnapshot(op snapOp, v interface{}) {
	for _, pop := range s.snapset {
		if pop.op != op {
			continue
		}
		switch t := v.(type) {
		case Matcher:
			if t.Match(pop.v) {
				log.Printf("WARN: possible double-journal attempt for %+v/%+v", pop.v, t)
				return
			}
		case interface{}:
			if t == pop.v {
				log.Printf("WARN: possible double-journal attempt for %+v/%+v", pop.v, t)
				return
			}
		}
	}
	s.snapset = append(s.snapset, snapOperation{op, v})
}

func snapshotClose(s *snapshot, ctx context.Context, c chan<- struct{}) {
	select {
	case <-ctx.Done():
	default:
		g := make(chan error, 2)
		s.reqFlushCh <- snapReqFlush{gate: g}
		select {
		case err := <-g:
			if err != nil {
				panic(err)
			}
		case <-ctx.Done():
			//TODO handle error
		}
	}
	c <- struct{}{}
}

func (s *snapshot) clearView() {
	s.snapset = make([]snapOperation, 0, len(s.snapset))
	for i := s.expList.SeekToFirst(); i != nil; i = s.expList.SeekToFirst() {
		if rr, ok := i.Key().(RR); ok {
			s.expList.Delete(rr)
			s.nameList.Delete(rr)
		}
		//i.Close()
	}
}

func (s *snapshot) runFlush(fl snapReqFlush) error {
	//log.Println("FLUSH")
	s.Cache.WLock()
	defer s.Cache.WUnlock()
	defer s.clearView()
	s.Cache.verbose = true
	for _, op := range s.snapset {
		switch op.op {
		case snapOpAdd:
			log.Printf("SNAP ADD: %+v", op.v)
			s.Cache.update(op.v)
		case snapOpDel:
			log.Printf("SNAP DEL: %+v", op.v)
			s.Cache.del(op.v)
		}
	}
	s.Cache.verbose = false
	return nil
}

func (s *snapshot) runUpdate(upd ...Matcher) error {
	for _, m := range upd {
		//log.Printf("UPDATE: %+v", m)
		adds, dels := cacheViewShadowUpdate(s.Cache, s.RRCacheView, m)
		for _, d := range dels {
			log.Printf("DEL: %+v", d)
			s.addToSnapshot(snapOpDel, d)
		}
		for _, a := range adds {
			log.Printf("ADD: %+v", a)
			s.addToSnapshot(snapOpAdd, a)
		}
	}

	return nil
}

func (s *snapshot) flushAsync(wait, resetExpireTimer bool) error {
	r := snapReqFlush{resetExpireTimer: resetExpireTimer, gate: make(chan error, 2)}
	go func() {
		s.reqFlushCh <- r
	}()

	if wait {
		return <-r.gate
	}
	return nil
}

func (s *snapshot) runExpire(now time.Time) (nexpired int) {
	var rr RR
	var ok bool

	l := s.Cache.RLock()
	defer l.RUnlock()

	i := s.Cache.expList.SeekToFirst()
	if i == nil {
		return
	}

	defer i.Close()
	for rr, ok = i.Key().(RR); ok; rr, ok = i.Key().(RR) {
		if rr.ExpireAt().After(now.Add(time.Duration(5000))) {
			return
		}
		nexpired++
		s.addToSnapshot(snapOpDel, rr)
		s.expList.Delete(rr)
		s.nameList.Delete(rr)
		if !i.Next() {
			break
		}
	}

	return
}

func (s *snapshot) getNextExpire() (when time.Duration, ok bool) {
	var rr RR
	l := s.Cache.RLock()
	defer l.RUnlock()

	i := s.Cache.expList.SeekToFirst()
	if i == nil {
		return
	}

	now := time.Now()
	if rr, ok = i.Key().(RR); ok {
		t := rr.ExpireAt()
		if t.Before(now) {
			return
		}
		when = t.Sub(now)
	}
	return
}

func (s *snapshot) run(ctx context.Context) {
	var C, expC <-chan time.Time
	var timer *time.Timer

	ticker := time.NewTicker(defaultSnapshotFlushInterval)
	defer ticker.Stop()

	for {
		if timer != nil {
			expC = timer.C
		}
		if ticker != nil {
			C = ticker.C
		}
		select {
		case <-ctx.Done():
			return
		case r := <-s.reqFlushCh:
			if ticker != nil {
				ticker.Stop()
			}
			if r.resetExpireTimer && timer != nil {
				timer.Stop()
				timer = nil
				expC = nil
			}
			ticker = time.NewTicker(defaultSnapshotFlushInterval)
			if len(s.snapset) > 0 {
				err := s.runFlush(r)
				if err != nil {
					r.gate <- err
				}
				close(r.gate)
			}
			if timer == nil {
				nextexp, ok := s.getNextExpire()
				log.Printf(" ---> NEXT EXPIRE @ %v [%v]", nextexp, ok)
				if ok {
					timer = time.NewTimer(nextexp)
				}
			}
		case r := <-s.reqUpdCh:
			//log.Printf("SNAP UPD: %+v", r.updSet)
			func() {
				defer func() {
					if e := recover(); e != nil {
						log.Fatal(e)
					}
				}()
				err := s.runUpdate(r.updSet...)
				if err != nil {
					log.Fatal(err)
					r.gate <- err
				}
				close(r.gate)
			}()
		case ts := <-expC:
			log.Printf("time to run expiration [%v]!", ts)
			expC = nil
			n := s.runExpire(ts)
			log.Printf("expired %d nodes", n)
			if n > 0 {
				// NB: run snapshot merge immediately
				ticker.Stop()
				C = nil
				ticker = nil
				timer = nil
				s.flushAsync(false, true)
			} else {
				nextexp, ok := s.getNextExpire()
				log.Printf(" ---> NEXT EXPIRE @ %v [%v]", nextexp, ok)
				if ok {
					timer = time.NewTimer(nextexp)
				}
			}
		case <-C:
			if len(s.snapset) > 0 {
				ticker.Stop()
				C = nil
				ticker = nil
				s.flushAsync(false, true)
			}
		}
	}
}

func snapshotStart(ctx context.Context, cache *RRCache, c chan<- struct{}) (*snapshot, context.Context) {
	var cf context.CancelFunc
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cf = context.WithCancel(ctx)

	snap := &snapshot{
		RRCacheView: newRRCacheView(),
		Cache:       cache,
		reqUpdCh:    make(chan snapReqUpd, 1),
		reqFlushCh:  make(chan snapReqFlush, 1),
		snapset:     make([]snapOperation, 0),
	}
	go func() {
		defer cf()
		defer snapshotClose(snap, ctx, c)
		snap.run(ctx)
	}()

	return snap, ctx
}
