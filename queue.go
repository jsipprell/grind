package main

type QueueValue func() interface{}

type queue struct {
	C <-chan QueueValue

	sem     chan struct{}
	done    chan struct{}
	cancel  chan struct{}
	pending chan interface{}
	c       chan<- QueueValue
}

func NewQueue(initialItems int) *queue {
	C := make(chan QueueValue, 0)
	q := &queue{
		C:       C,
		c:       C,
		sem:     make(chan struct{}, 1),
		done:    make(chan struct{}, 1),
		cancel:  make(chan struct{}, 1),
		pending: make(chan interface{}, initialItems),
	}
	q.sem <- struct{}{}
	return q
}

func (q *queue) push(v interface{}, gate chan<- struct{}) {
	if gate != nil {
		defer close(gate)
	}
	select {
	case <-q.done:
		panic("queue has terminated")
	default:
	}

	select {
	case q.pending <- v:
		if gate != nil {
			gate <- struct{}{}
		}
	case <-q.done:
		return
	}

	select {
	case <-q.sem:
		go q.run(q.sem)
	default:
	}
}

func (q *queue) Push(v interface{}) {
	q.push(v, nil)
}

func (q *queue) PushAsync(v interface{}) <-chan struct{} {
	ch := make(chan struct{}, 2)
	go q.push(v, ch)
	return ch
}

func releaseQueueSem(sem chan<- struct{}) { sem <- struct{}{} }

func (q *queue) run(sem chan<- struct{}) {
	defer releaseQueueSem(sem)
	defer close(q.c)
	defer close(q.done)

	for {
		select {
		case <-q.cancel:
			return
		case <-q.done:
			panic("this should never happen")
		case q.c <- QueueValue(q.pop):
		}
	}
}

func (q *queue) pop() interface{} {
	select {
	case v := <-q.pending:
		return v
	default:
	}
	return nil
}

func (q *queue) Cancel() {
	select {
	case <-q.done:
		return
	default:
		select {
		case <-q.sem:
			go q.run(q.sem)
		default:
		}
	}

	select {
	case q.cancel <- struct{}{}:
	case <-q.done:
		return
	}
	<-q.done
}

func (q *queue) Len() int {
	return len(q.pending)
}
