package factotum

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionLifecycle(t *testing.T) {
	sessions := NewSessions()
	fid := uint32(1)

	// 1. Set Session
	sess := &Session{
		FID:   fid,
		User:  "alice",
		State: "start",
	}
	sessions.Set(fid, sess)

	// 2. Get Session
	got, ok := sessions.Get(fid)
	assert.True(t, ok)
	assert.Equal(t, sess, got)

	// 3. Delete Session
	sessions.Delete(fid)
	_, ok = sessions.Get(fid)
	assert.False(t, ok)
}

func TestSessionConcurrency(t *testing.T) {
	sessions := NewSessions()
	var wg sync.WaitGroup

	// Concurrently Add/Get/Delete
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(fid uint32) {
			defer wg.Done()
			sess := &Session{FID: fid}
			sessions.Set(fid, sess)

			got, ok := sessions.Get(fid)
			if ok {
				assert.Equal(t, fid, got.FID)
			}

			sessions.Delete(fid)
		}(uint32(i))
	}

	wg.Wait()
}
