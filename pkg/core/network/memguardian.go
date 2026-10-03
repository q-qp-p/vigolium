package network

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/utils/env"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/projectdiscovery/utils/memguardian"
	"go.uber.org/zap"
)

var (
	MaxThreadsOnLowMemory          = env.GetEnvOrDefault("MEMGUARDIAN_THREADS", 30)
	MaxBytesBufferAllocOnLowMemory = env.GetEnvOrDefault("MEMGUARDIAN_ALLOC", 200)

	// memMu guards the guardian's lifecycle handles. They are package globals
	// written by Start and read by Stop, while the goroutine Start launched is
	// still running — so two overlapping scan lifecycles in one process (a server
	// starting a second scan as the first tears down) raced on them, and a Start
	// arriving before the previous goroutine noticed its cancellation left that
	// goroutine on a ticker nothing would ever stop.
	memMu      sync.Mutex
	memTimer   *time.Ticker
	cancelFunc context.CancelFunc
)

func StartActiveMemGuardian(ctx context.Context) {
	if memguardian.DefaultMemGuardian == nil {
		zap.L().Warn("memguardian not found, skipping")
		return
	}

	memMu.Lock()
	defer memMu.Unlock()
	// Already running: a second Start would orphan the first goroutine.
	if cancelFunc != nil {
		return
	}

	timer := time.NewTicker(time.Second * 15) // default 30s
	ctx, cancel := context.WithCancel(ctx)
	memTimer, cancelFunc = timer, cancel

	// The ticker and context are CAPTURED rather than read from the globals: a
	// later Stop/Start pair reassigns those while this goroutine still runs.
	go func() {
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if IsLowOnMemory() {
					_ = GlobalGuardBytesBufferAlloc()
				} else {
					GlobalRestoreBytesBufferAlloc()
				}
			}
		}
	}()
}

func StopActiveMemGuardian() {
	if memguardian.DefaultMemGuardian == nil {
		return
	}

	memMu.Lock()
	timer, cancel := memTimer, cancelFunc
	memTimer, cancelFunc = nil, nil
	memMu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	if cancel != nil {
		cancel()
	}
}

func IsLowOnMemory() bool {
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}
	return false
}

// GuardThreadsOrDefault returns reduced thread count when memory is low
func GuardThreadsOrDefault(current int) int {
	if MaxThreadsOnLowMemory > 0 {
		return MaxThreadsOnLowMemory
	}

	fraction := int(current / 5)
	if fraction > 0 {
		return fraction
	}

	return 1
}

var muGlobalChange sync.Mutex

// GlobalGuardBytesBufferAlloc reduces buffer pool size when memory is low
func GlobalGuardBytesBufferAlloc() error {
	if !muGlobalChange.TryLock() {
		return nil
	}
	defer muGlobalChange.Unlock()

	// if current capacity was not reduced decrease it
	if MaxBytesBufferAllocOnLowMemory > 0 && httputil.DefaultBufferSize == httputil.GetPoolSize() {
		zap.L().Info("reducing bytes.buffer pool size", zap.Int("new_size", MaxBytesBufferAllocOnLowMemory))
		delta := httputil.GetPoolSize() - int64(MaxBytesBufferAllocOnLowMemory)
		return httputil.ChangePoolSize(-delta)
	}

	return nil
}

// GlobalRestoreBytesBufferAlloc restores buffer pool size when memory is normal
func GlobalRestoreBytesBufferAlloc() {
	if !muGlobalChange.TryLock() {
		return
	}
	defer muGlobalChange.Unlock()

	if httputil.DefaultBufferSize != httputil.GetPoolSize() {
		delta := httputil.DefaultBufferSize - httputil.GetPoolSize()
		zap.L().Info("restoring bytes.buffer pool size", zap.Int64("new_size", httputil.DefaultBufferSize))
		_ = httputil.ChangePoolSize(delta)
	}
}
