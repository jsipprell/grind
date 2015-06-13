package db

import (
	"io"
	"time"

	"github.com/petar/GoLLRB/llrb"
)

type Expiring interface {
	Item
	ExpireAt() time.Time
}

type ExpireEqualing interface {
	Expiring
	Equaling
}

type TTLStore struct {
	*llrb.LLRB
}

type ttlAdapter struct {
	Expiring

	exp int64
}

type ttlMatchGreaterOrEqual time.Time

type ttlIterator struct {
	*iterator
}

func (t *ttlAdapter) Equal(v interface{}) bool {
	switch exp := v.(type) {
	case *ttlAdapter:
		return exp.Expiring == t.Expiring
	case Expiring:
		return exp == t.Expiring
	}
	return v == t.Expiring
}

func (t *ttlAdapter) Less(v interface{}) bool {
	switch j := v.(type) {
	case *ttlAdapter:
		return t.exp < j.exp
	case Expiring:
		return t.exp < j.ExpireAt().UnixNano()
	case time.Time:
		return t.exp < j.UnixNano()
	case uint64:
		return t.exp < int64(j)
	case int64:
		return t.exp < j
	}
	panic("unsupported type")
}

func (ttl ttlMatchGreaterOrEqual) Less(v interface{}) bool {
	switch j := v.(type) {
	case *ttlAdapter:
		return time.Time(ttl).UnixNano() < j.exp
	case Expiring:
		return time.Time(ttl).Before(j.ExpireAt())
	case time.Time:
		return time.Time(ttl).Before(j)
	case uint64:
		return time.Time(ttl).UnixNano() < int64(j)
	case int64:
		return time.Time(ttl).UnixNano() < j
	}
	panic("unsupported type")
}

func (ttl ttlMatchGreaterOrEqual) Match(v interface{}) bool {
	return !ttl.Less(v)
}

// Returns a new TTL index store which order objects by future time,
// soonest first.
func NewTTLStore() *TTLStore {
	return &TTLStore{llrb.New()}
}

func adapt(v interface{}) *ttlAdapter {
	switch t := v.(type) {
	case *ttlAdapter:
		return t
	case Expiring:
		return &ttlAdapter{Expiring: t, exp: t.ExpireAt().UnixNano()}
	}
	panic("unsupported type")
}

// Set (replace if already exists) a new expiring object.
func (ts *TTLStore) Set(i Expiring) {
	ts.ReplaceOrInsert(llrbitem{adapt(i)})
}

// Add (don't replace) an expiring object
func (ts *TTLStore) Add(i Expiring) {
	ts.InsertNoReplace(llrbitem{adapt(i)})
}

// Return the object that will expire soonest (or has expired)
func (ts *TTLStore) First() Expiring {
	i := ts.Min().(llrbitem).Item
	if i != nil {
		return i.(*ttlAdapter).Expiring
	}
	return nil
}

// Return the object that will expire last.
func (ts *TTLStore) Last() Expiring {
	i := ts.Max().(llrbitem).Item
	if i != nil {
		return i.(*ttlAdapter).Expiring
	}
	return nil
}

func (ts *TTLStore) getFirstGreaterOrEqualTo(key ExpireEqualing) (item *ttlAdapter, ok bool) {
	ts.AscendGreaterOrEqual(llrbitem{adapt(key)}, func(i llrb.Item) bool {
		item = i.(llrbitem).Item.(*ttlAdapter)
		ok = true
		return false
	})

	return
}

func (ts *TTLStore) getFirstEqualTo(key ExpireEqualing) (item *ttlAdapter, ok bool) {
	ts.AscendGreaterOrEqual(llrbitem{adapt(key)}, func(i llrb.Item) bool {
		if ok = key.Equal(i.(llrbitem).Item.(*ttlAdapter).Expiring); ok {
			item = i.(llrbitem).Item.(*ttlAdapter)
		}
		return false
	})

	return
}

func (ls *TTLStore) getFirstMatching(m Matching) (item *ttlAdapter, ok bool) {
	ls.AscendGreaterOrEqual(llrbitem{m.(Item)}, func(i llrb.Item) bool {
		if ok = m.Match(i.(llrbitem).Item.(*ttlAdapter).Expiring); ok {
			item = i.(llrbitem).Item.(*ttlAdapter)
		}
		return false
	})

	return
}

// Retrieve an object from the ttl index, objects are looked up first by
// expiration but then either equality or matching is used (depending on
// if the key implements Equaling or Matching) to ensure the correct
// object is returned.
func (ts *TTLStore) Get(key Item) (exp Expiring, ok bool) {
	var a *ttlAdapter
	switch t := key.(type) {
	case ExpireEqualing:
		a, ok = ts.getFirstEqualTo(t)
	case Matching:
		a, ok = ts.getFirstMatching(t)
	case interface{}:
		panic("unsupported key type")
	}

	if ok {
		exp = a.Expiring
	}
	return
}

func (ts *TTLStore) getKeys(key interface{}) []*ttlAdapter {
	var iterfn llrb.ItemIterator

	items := make([]*ttlAdapter, 0, 1)

	switch t := key.(type) {
	case Equaling:
		iterfn = func(i llrb.Item) (ok bool) {
			if ok = t.Equal(i.(llrbitem).Item); ok {
				items = append(items, i.(llrbitem).Item.(*ttlAdapter))
			}
			return
		}
	case Matching:
		iterfn = func(i llrb.Item) (ok bool) {
			if ok = t.Match(i.(llrbitem).Item); ok {
				items = append(items, i.(llrbitem).Item.(*ttlAdapter))
			}
			return
		}
	}
	if iterfn == nil {
		panic("unsupported type")
	}

	ts.AscendGreaterOrEqual(llrbitem{adapt(key)}, iterfn)
	return items
}

// Delete all objects which match (or are exactly equal to) `key`.
func (ts *TTLStore) DeleteAll(key Item) bool {
	var count int
	for _, i := range ts.getKeys(key) {
		if ts.LLRB.Delete(llrbitem{i}) != nil {
			count++
		}
	}

	return count > 0
}

// Delete one object that is exactly equal to `key`.
func (ts *TTLStore) Delete(key ExpireEqualing) (Expiring, bool) {
	var exp Expiring
	item, ok := ts.getFirstEqualTo(key)
	if ok {
		if i := ts.LLRB.Delete(llrbitem{item}); i != nil {
			exp = i.(llrbitem).Item.(*ttlAdapter).Expiring
		} else {
			ok = false
		}
	}

	return exp, ok
}

// Return all objects which exactly equal or match `key`.
func (ts *TTLStore) GetAll(key Item) []Expiring {
	keys := ts.getKeys(key)
	if len(keys) > 0 {
		items := make([]Expiring, len(keys))
		for i, j := range keys {
			items[i] = j.Expiring
		}
		return items
	}

	return nil
}

// Return all objects which match any of the supplied matching criteria.
func (ts *TTLStore) GetMatching(matches ...MatchingItem) []Expiring {
	items := make([]Expiring, 0, 1)
	dedup := make(map[Expiring]struct{})

	for _, m := range matches {
		for _, i := range ts.getKeys(labelMatch{m: m}) {
			if _, ok := dedup[i]; !ok {
				dedup[i.Expiring] = struct{}{}
				items = append(items, i.Expiring)
			}
		}
	}
	return items
}

// Delete all objects which match any of the supplied matching criteria.
func (ts *TTLStore) DeleteMatching(matches ...MatchingItem) int {
	var count int

	for _, m := range matches {
		for _, i := range ts.getKeys(labelMatch{m: m}) {
			if ts.LLRB.Delete(llrbitem{i}) != nil {
				count++
			}
		}
	}

	return count
}

// Returns an iterator over all items in the tree
// in tree-invariant order starting with the first item.
func (ts *TTLStore) SeekFirst() Iterator {
	return &ttlIterator{
		&iterator{
			rb: ts.LLRB,
			stepfunc: func(_ llrb.Item, ii llrb.ItemIterator) {
				ts.AscendRange(llrb.Inf(-1), llrb.Inf(1), ii)
			},
			gate: make(chan struct{}, 0),
		},
	}
}

// Returns a reverse order iterator over all items in
// the tree starting with the last.
func (ts *TTLStore) SeekLast() Iterator {
	return &ttlIterator{
		&iterator{
			rb: ts.LLRB,
			stepfunc: func(_ llrb.Item, ii llrb.ItemIterator) {
				ts.DescendLessOrEqual(llrb.Inf(1), ii)
			},
			gate: make(chan struct{}, 0),
		},
	}
}

// Returns an ascending iterator over all items in the
// tree in invariant order, starting with the first item
// greater than or equal to the specified key.
func (ts *TTLStore) Seek(key interface{}) Iterator {
	var start Expiring
	var ok bool

	switch t := key.(type) {
	case ExpireEqualing:
		if start, ok = ts.getFirstGreaterOrEqualTo(t); !ok {
			return &ttlIterator{&iterator{err: io.EOF}}
		}
	case Matching:
		if start, ok = ts.getFirstMatching(t); !ok {
			return &ttlIterator{&iterator{err: ErrNoMatch}}
		}
	case time.Time:
		if start, ok = ts.getFirstMatching(ttlMatchGreaterOrEqual(t)); !ok {
			return &ttlIterator{&iterator{err: ErrNoMatch}}
		}
	}

	return &ttlIterator{
		&iterator{
			rb:    ts.LLRB,
			start: start,
			gate:  make(chan struct{}, 0),
		},
	}
}

// Completely reset the ttl index
func (ts *TTLStore) Clear() {
	for ts.Len() > 0 {
		ts.DeleteMin()
	}
}

// returns an ascending iterator which sequences all
// items in the that equal or match a key (depending
// on if the key is Equaling or Matching).
func (ts *TTLStore) Find(key interface{}) Iterator {
	var start Expiring
	var ok bool

	switch t := key.(type) {
	case ExpireEqualing:
		if start, ok = ts.getFirstEqualTo(t); !ok {
			return &ttlIterator{&iterator{err: io.EOF}}
		}
		return &ttlIterator{
			&iterator{
				rb:    ts.LLRB,
				start: start,
				gate:  make(chan struct{}, 0),
				get: func(i llrb.Item) (Item, bool) {
					return i.(llrbitem).Item, t.Equal(i.(llrbitem).Item)
				},
			},
		}
	case Matching:
		if start, ok = ts.getFirstMatching(t); !ok {
			return &iterator{err: io.EOF}
		}
		return &ttlIterator{
			&iterator{
				rb:    ts.LLRB,
				start: start,
				gate:  make(chan struct{}, 0),
				get: func(i llrb.Item) (Item, bool) {
					return i.(llrbitem).Item, t.Match(i.(llrbitem).Item)
				},
			},
		}
	case time.Time:
		m := ttlMatchGreaterOrEqual(t)
		if start, ok = ts.getFirstMatching(m); !ok {
			return &ttlIterator{&iterator{err: io.EOF}}
		}
		return &ttlIterator{
			&iterator{
				rb:    ts.LLRB,
				start: start,
				gate:  make(chan struct{}, 0),
				get: func(i llrb.Item) (Item, bool) {
					return i.(llrbitem).Item, m.Match(i.(llrbitem).Item)
				},
			},
		}
	}
	panic("unsupported seek type")
}

func (i *ttlIterator) convert(v interface{}) Expiring {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case llrb.Item:
		return t.(llrbitem).Item.(*ttlAdapter).Expiring
	case Item:
		return t.(*ttlAdapter).Expiring
	}
	panic("invalid ttl type")
}

func (i *ttlIterator) Next() (Item, bool) {
	item, ok := i.iterator.Next()
	return i.convert(item), ok
}
