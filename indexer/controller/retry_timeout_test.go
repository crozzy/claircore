package controller

import (
	"context"
	"testing"
	"time"

	"github.com/quay/zlog"
	"go.uber.org/mock/gomock"

	"github.com/quay/claircore"
	indexer "github.com/quay/claircore/test/mock/indexer"
)

// TestRescanTimeoutPersistsEmptyReport reproduces the behavior reported in
// https://github.com/quay/claircore/issues/1124 where a timeout while
// retrieving an existing IndexReport during CheckManifest causes the controller
// to persist an (empty) IndexReport and then terminate without retrying the
// state transition.
func TestRescanTimeoutPersistsEmptyReport(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	ctrl := gomock.NewController(t)
	store := indexer.NewMockStore(ctrl)
	fa := indexer.NewMockFetchArena(ctrl)
	realizer := indexer.NewMockRealizer(ctrl)

	realizer.EXPECT().Close()
	fa.EXPECT().Realizer(gomock.Any()).Return(realizer)

	// Arrange a manifest that the store believes is already scanned.
	store.EXPECT().ManifestScanned(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)
	// Simulate a timeout retrieving the stored IndexReport.
	store.EXPECT().IndexReport(gomock.Any(), gomock.Any()).
		Return(nil, false, context.DeadlineExceeded)

	// Desired behavior: do not persist an empty IndexReport on timeout.
	store.EXPECT().SetIndexReport(gomock.Any(), gomock.Any()).Times(0)

	// Use a short deadline so the controller exits during the retry backoff select.
	tctx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()

	c := New(&indexer.Options{
		Store:      store,
		FetchArena: fa,
	})

	rep, err := c.Index(tctx, &claircore.Manifest{})
	if err == nil {
		t.Fatalf("expected non-nil error; want controller to not persist on timeout: %v", err)
	}
	_ = rep
}
