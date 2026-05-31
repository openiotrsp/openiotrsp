package memory_test

import (
	"testing"

	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
	"github.com/openiotrsp/openiotrsp/storage/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Run(t, func(t testing.TB) storage.Store {
		t.Helper()
		return memory.New()
	})
}
