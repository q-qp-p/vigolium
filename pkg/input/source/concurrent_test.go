package source

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/work"
	"go.uber.org/goleak"
)

// blockingSource parks in Next until its context is cancelled — the behaviour
// ConcurrentMultiSource exists for (queue sources that never reach EOF).
type blockingSource struct {
	mu      sync.Mutex
	closed  bool
	entered chan struct{}
	once    sync.Once
}

func newBlockingSource() *blockingSource {
	return &blockingSource{entered: make(chan struct{})}
}

func (b *blockingSource) Next(ctx context.Context) (*work.WorkItem, error) {
	b.once.Do(func() { close(b.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (b *blockingSource) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *blockingSource) wasClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// infiniteSource always has another item, so it only stops when its context does.
type infiniteSource struct {
	mu     sync.Mutex
	closed bool
	served int
}

func (s *infiniteSource) Next(ctx context.Context) (*work.WorkItem, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	s.mu.Lock()
	s.served++
	s.mu.Unlock()
	return work.NewWithModules(nil, []string{"inf"}), nil
}

func (s *infiniteSource) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *infiniteSource) wasClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// TestConcurrentMultiSource_CancelStopsReadersWithoutClosingChildren is the whole
// point of handing the constructor a context: the phase that owns the readers can
// end them without calling Close, which would tear down child sources (notably the
// runner's shared inputSource) that outlive the phase.
func TestConcurrentMultiSource_CancelStopsReadersWithoutClosingChildren(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	blocked := newBlockingSource()
	infinite := &infiniteSource{}

	ctx, cancel := context.WithCancel(context.Background())
	cs := NewConcurrentMultiSource(ctx, blocked, infinite)

	// Both readers are live: one parked, one producing.
	<-blocked.entered
	_, err := cs.Next(context.Background())
	require.NoError(t, err)

	cancel()

	// Next drains whatever the infinite source already buffered and then ends.
	deadline := time.Now().Add(time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("Next did not reach EOF within 1s of cancelling the parent context")
		}
		_, err = cs.Next(context.Background())
		if err != nil {
			break
		}
	}
	assert.ErrorIs(t, err, io.EOF, "cancelled readers close the channel, which is EOF")

	assert.False(t, blocked.wasClosed(), "cancelling must not close a child source")
	assert.False(t, infinite.wasClosed(), "cancelling must not close a child source")

	// Close is still the thing that closes children, and stays idempotent.
	require.NoError(t, cs.Close())
	assert.True(t, blocked.wasClosed())
	assert.True(t, infinite.wasClosed())
	require.NoError(t, cs.Close())
}

// TestConcurrentMultiSource_NilContextDefaultsToBackground: a nil context means
// the readers outlive every caller, which is only ever right in a test — but it
// must not panic.
func TestConcurrentMultiSource_NilContextDefaultsToBackground(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	a := newFakeSource("a1")
	//nolint:staticcheck // deliberately exercising the nil-context fallback
	cs := NewConcurrentMultiSource(nil, a)

	item, err := cs.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, item)

	require.NoError(t, cs.Close())
	assert.True(t, a.closed)
}
