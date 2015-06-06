package barricade

import (
	"math/rand"
	"testing"
	"time"
)

const factor = time.Millisecond

type testWaitVal struct {
	min, max int
}

type timeWaiter interface {
	Sleep()
	After() <-chan time.Time
	Get() time.Duration
}

func (t testWaitVal) Sleep() {
	time.Sleep(t.Get())
}

func (t testWaitVal) After() <-chan time.Time {
	return time.After(t.Get())
}

func (t testWaitVal) Get() time.Duration {
	var tmin, tmax time.Duration

	tmin = time.Duration(t.min) * factor
	tmax = time.Duration(t.max) * factor
	return time.Duration(rand.Int63n((int64(tmax) - int64(tmin)) + int64(tmin)))
}

func helperStartWriters(b *barricade, nwriters int, freq, sleep timeWaiter, t *testing.T) chan<- struct{} {
	C := make(chan struct{}, 1)

	for i := 0; i < nwriters; i++ {
		go func(n int) {
			var f timeWaiter = testWaitVal{1, 1}
			for {
				select {
				case <-C:
					return
				case ts := <-f.After():
					f = freq
					func(delay time.Duration, ts time.Time) {
						t.Logf("writer %d: TRY WRITELOCK [%v]", n, ts)
						b.WLock()
						defer func() {
							t.Logf("writer %d: RELEASE WRITELOCK (%+v, elapsed %v)", n, b.lock, time.Now().Sub(ts))
						}()
						//t.Logf("PENDING = %d", len(b.lock.pending))
						defer b.WUnlock()
						defer t.Logf("writer %d: barricade release writelock (%+v)", n, b.lock)
						t.Logf("writer %d: ACQUIRED barricade at %v", n, ts)
						t.Logf("writer %d: barricade writelock, working for %v", n, delay)
						select {
						case <-C:
						case <-time.After(delay):
						}
					}(sleep.Get(), ts)
				}
			}
		}(i + 1)
	}

	return C
}

func helperStartReaders(b *barricade, nreaders int, freq, sleep timeWaiter, t *testing.T) chan<- struct{} {
	C := make(chan struct{}, 1)

	for i := 0; i < nreaders; i++ {
		go func(n int) {
			for {
				select {
				case <-C:
					return
				case ts := <-freq.After():
					func(delay time.Duration, ts time.Time) {
						unlock := b.RLock()
						if unlock == nil {
							panic("bad barricade lock")
						}
						t.Logf("reader %d: aqcuired barricade at %v", n, ts)
						//t.Logf("PENDING = %d", len(b.lock.pending))
						defer unlock.RUnlock()
						defer t.Logf("reader %d: released barricade (elapsed %v)", n, time.Now().Sub(ts))
						t.Logf("reader %d: barricade readlock, working for %v", n, delay)
						select {
						case <-C:
						case <-time.After(delay):
						}
					}(sleep.Get(), ts)
				}
			}
		}(i + 1)
	}
	return C
}

func TestBarricadeReaders(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	b := New(5).(*barricade)
	C := helperStartReaders(b, 5, testWaitVal{80, 365}, testWaitVal{1400, 2200}, t)
	defer close(C)
	time.Sleep(time.Duration(5000) * time.Millisecond)
}

func TestBarricadeWriters(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	b := New(20).(*barricade)
	CW := helperStartWriters(b, 1, testWaitVal{200, 250}, testWaitVal{2000, 2400}, t)
	defer close(CW)
	CR := helperStartReaders(b, 20, testWaitVal{50, 80}, testWaitVal{200, 250}, t)
	defer close(CR)

	time.Sleep(time.Duration(10000) * time.Millisecond)
}
