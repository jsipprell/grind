package db

import (
	"errors"

	"github.com/petar/GoLLRB/llrb"
)

var (
	ErrNoMatch = errors.New("no match")
)

// Represents the basic item that can be stored.
type Item interface {
	Less(interface{}) bool
}

type llrbitem struct {
	Item Item
}

type NamedItem interface {
	Item
	Name() string
}

// For lookup/indexing, the Equaling interface represents keys that match explicitly and exactly.
type Equaling interface {
	Equal(interface{}) bool
}

// For lookup/indexing, the Matching interface represents keys that match more loosely.
type Matching interface {
	Match(interface{}) bool
}

// A storage item can itself by weakly matching.
type MatchingItem interface {
	Item
	Matching
}

// Iterators are return by Seek and Find methods on the trees themselves.
type Iterator interface {
	Next() (Item, bool)
	Err() error
	Close() error
}

func (l llrbitem) Less(i llrb.Item) bool {
	switch ii := i.(type) {
	case llrbitem:
		return l.Item.Less(ii.Item)
	case Item:
		return l.Item.Less(ii)
	}
	return !i.Less(l) && i != l
}
