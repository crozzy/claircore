package rhel

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/quay/zlog"
)

func TestUpdater(t *testing.T) {
	ctx := zlog.Test(context.Background(), t)

	gfu := genericFileUpdater{
		url:  DefaultName2ReposMappingURL,
		name: "repo-to-cpe",
	}
	if gfu.Name() != "generic-repo-to-cpe" {
		t.Fatal("name wrong")
	}

	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	_, err := gfu.Fetch(ctx, zipWriter, "", http.DefaultClient)
	if err != nil {
		t.Error(err)
	}
	err = zipWriter.Close()
	if err != nil {
		t.Error(err)
	}

	err = os.WriteFile("output.zip", buf.Bytes(), 0644)
	if err != nil {
		panic(err)
	}
}
