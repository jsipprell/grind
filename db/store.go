package db

import (
	"io"

	"github.com/petar/GoLLRB/llrb"
)

type iterator struct {
	rb    *llrb.LLRB
	start Item
	err   error
	get   func(llrb.Item) (Item, bool)
	gate  chan struct{}
	c     <-chan Item

	stepfunc func(llrb.Item, llrb.ItemIterator)
}

type Store struct {
	*llrb.LLRB
}

type labelMatch struct {
	m Matching
	i Item
}

// Allocate a new object store which will be ordered by primary key.
func NewStore() *Store {
	return &Store{LLRB: llrb.New()}
}

// Add an object to the store, the first existing object (if any) will be replaced
// with the new one.
func (ls *Store) Set(i NamedItem) {
	ls.ReplaceOrInsert(llrbitem{i})
}

// Add an object to the store, do not replace any existing objects. This will
// cause key duplication but this is acceptable under certain constraints.
func (ls *Store) Add(i NamedItem) {
	ls.InsertNoReplace(llrbitem{i})
}

// Return the first item in the store
func (ls *Store) First() Item {
	return ls.Min().(llrbitem).Item
}

// Return the last item in the store
func (ls *Store) Last() Item {
	return ls.Max().(llrbitem).Item
}

// Returns an iterator over all items in the tree
// in tree-invariant order starting with the first item.
func (ls *Store) SeekFirst() Iterator {
	return &iterator{
		rb: ls.LLRB,
		stepfunc: func(_ llrb.Item, ii llrb.ItemIterator) {
			ls.AscendRange(llrb.Inf(-1), llrb.Inf(1), ii)
		},
		gate: make(chan struct{}, 0),
	}
}

// Returns a reverse order iterator over all items in
// the tree starting with the last.
func (ls *Store) SeekLast() Iterator {
	return &iterator{
		rb: ls.LLRB,
		stepfunc: func(_ llrb.Item, ii llrb.ItemIterator) {
			ls.DescendLessOrEqual(llrb.Inf(1), ii)
		},
		gate: make(chan struct{}, 0),
	}
}

// Returns an ascending iterator over all items in the
// tree in invariant order, starting with the first item
// greater than or equal to the specified key.
func (ls *Store) Seek(key Item) Iterator {
	var start Item
	var ok bool

	switch t := key.(type) {
	case Equaling:
		if start, ok = ls.getFirstGreaterOrEqualTo(t); !ok {
			return &iterator{err: io.EOF}
		}
	case Matching:
		if start, ok = ls.getFirstMatching(t); !ok {
			return &iterator{err: ErrNoMatch}
		}
	}

	return &iterator{
		rb:    ls.LLRB,
		start: start,
		gate:  make(chan struct{}, 0),
	}
}

// returns an ascending iterator which sequences all
// items in the that equal or match a key (depending
// on if the key is Equaling or Matching).
func (ls *Store) Find(key Item) Iterator {
	var start Item
	var ok bool

	switch t := key.(type) {
	case Equaling:
		if start, ok = ls.getFirstEqualTo(t); !ok {
			return &iterator{err: io.EOF}
		}
		return &iterator{
			rb:    ls.LLRB,
			start: start,
			gate:  make(chan struct{}, 0),
			get: func(i llrb.Item) (Item, bool) {
				return i.(llrbitem).Item, t.Equal(i.(llrbitem).Item)
			},
		}
	case Matching:
		if start, ok = ls.getFirstMatching(t); !ok {
			return &iterator{err: io.EOF}
		}
		return &iterator{
			rb:    ls.LLRB,
			start: start,
			gate:  make(chan struct{}, 0),
			get: func(i llrb.Item) (Item, bool) {
				return i.(llrbitem).Item, t.Match(i.(llrbitem).Item)
			},
		}
	}
	panic("unsupported seek type")
}

func (ls *Store) getFirstGreaterOrEqualTo(key Equaling) (item Item, ok bool) {
	ls.AscendGreaterOrEqual(llrbitem{key.(Item)}, func(i llrb.Item) bool {
		item = i.(llrbitem).Item
		ok = true
		return false
	})

	return
}

func (ls *Store) getFirstEqualTo(key Equaling) (item Item, ok bool) {
	ls.AscendGreaterOrEqual(llrbitem{key.(Item)}, func(i llrb.Item) bool {
		if ok = key.Equal(i.(llrbitem).Item); ok {
			item = i.(llrbitem).Item
		}
		return false
	})

	return
}

func (ls *Store) getFirstMatching(m Matching) (item Item, ok bool) {
	ls.AscendGreaterOrEqual(llrbitem{m.(Item)}, func(i llrb.Item) bool {
		if ok = m.Match(i.(llrbitem).Item); ok {
			item = i.(llrbitem).Item
		}
		return false
	})

	return
}

// Return the first item that equals or matches the supplied key.
func (ls *Store) Get(key Item) (Item, bool) {
	switch t := key.(type) {
	case Equaling:
		return ls.getFirstEqualTo(t)
	case Matching:
		return ls.getFirstMatching(t)
	}
	panic("unsupported key type")
}

func (ls *Store) getKeys(key Item) []Item {
	var iterfn llrb.ItemIterator

	items := make([]Item, 0, 1)

	switch t := key.(type) {
	case Equaling:
		iterfn = func(i llrb.Item) (ok bool) {
			if ok = t.Equal(i.(llrbitem).Item); ok {
				items = append(items, i.(llrbitem).Item)
			}
			return
		}
	case Matching:
		iterfn = func(i llrb.Item) (ok bool) {
			if ok = t.Match(i.(llrbitem).Item); ok {
				items = append(items, i.(llrbitem).Item)
			}
			return
		}
	}
	if iterfn == nil {
		panic("unsupported type")
	}

	ls.AscendGreaterOrEqual(llrbitem{key}, iterfn)
	return items
}

// Completely reset the object store so it contains no objects.
func (ls *Store) Clear() {
	for ls.Len() > 0 {
		ls.DeleteMin()
	}
}

// Delete all objects from the store that equal or match `key`.
func (ls *Store) DeleteAll(key Item) bool {
	var count int
	for _, i := range ls.getKeys(key) {
		if ls.LLRB.Delete(llrbitem{i}) != nil {
			count++
		}
	}

	return count > 0
}

// Delete one object from the store that exactly matches `key`
func (ls *Store) Delete(key Equaling) (Item, bool) {
	item, ok := ls.getFirstEqualTo(key)
	if ok {
		if i := ls.LLRB.Delete(llrbitem{item}); i != nil {
			item = i.(llrbitem).Item
		} else {
			ok = false
		}
	}

	return item, ok
}

// Return a slice of all objects which equal or match `key`.
func (ls *Store) GetAll(key Item) []Item {
	return ls.getKeys(key)
}

// Return a slice of all objects which *any* of the supplied
// matches match on (inclusive matching).
func (ls *Store) GetMatching(matches ...MatchingItem) []Item {
	items := make([]Item, 0, 1)
	dedup := make(map[Item]struct{})

	for _, m := range matches {
		for _, i := range ls.getKeys(labelMatch{m: m, i: m.(Item)}) {
			if _, ok := dedup[i]; !ok {
				dedup[i] = struct{}{}
				items = append(items, i)
			}
		}
	}
	return items
}

// Delete all objects which match for any supplied match.
func (ls *Store) DeleteMatching(matches ...MatchingItem) int {
	var count int

	for _, m := range matches {
		for _, i := range ls.getKeys(labelMatch{m: m, i: m.(Item)}) {
			if ls.LLRB.Delete(llrbitem{i}) != nil {
				count++
			}
		}
	}

	return count
}

func (lm labelMatch) Match(v interface{}) bool {
	return lm.m.Match(v)
}

func (lm labelMatch) Less(v interface{}) bool {
	return lm.i.Less(v)
}

// Return the next object in order in the index unless the iterator
// is in descending mode, in which case the previous will be returned.
// false is returned for the second argument when iteration is
// exhausted.
func (i *iterator) Next() (Item, bool) {
	select {
	case _, ok := <-i.gate:
		if !ok && (i.c == nil || len(i.c) == 0) {
			return nil, false
		}
	default:
		if i.c == nil {
			c := make(chan Item, 0)
			if i.stepfunc == nil {
				i.stepfunc = func(pivot llrb.Item, iterate llrb.ItemIterator) {
					i.rb.AscendRange(pivot, llrb.Inf(1), iterate)
				}
			}
			if i.get == nil {
				i.get = func(i llrb.Item) (Item, bool) {
					return i.(llrbitem).Item, true
				}
			}
			go i.run(c)
			i.c = c
		}
	}

	j, ok := <-i.c
	if !ok {
		if i.err == nil {
			i.err = io.EOF
		}
		defer close(i.gate)
		return nil, ok
	}
	return j, ok
}

// Returns io.EOF if no results available, otherwise ErrNoMatch in some
// specific failured modes.
func (i *iterator) Err() error {
	return i.err
}

// Release any resources used by the iterator. This should be called
// in a defer to avoid leaking goroutines.
func (i *iterator) Close() error {
	select {
	case <-i.gate:
	default:
		close(i.gate)
	}
	return i.err
}

func finalizeIterator(i *iterator, out chan<- Item) {
	defer close(out)
	i.start = nil
	i.stepfunc = nil
	i.rb = nil
}

func (i *iterator) run(out chan<- Item) {
	var start llrb.Item
	defer finalizeIterator(i, out)
	if i.start != nil {
		start = llrbitem{i.start}
	}

	i.stepfunc(start, func(j llrb.Item) bool {
		item, ok := i.get(j)
		if ok {
			select {
			case out <- item:
			case <-i.gate:
				return false
			}
		}
		return ok
	})
}
