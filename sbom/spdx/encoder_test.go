package spdx

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/go-cmp/cmp"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/quay/claircore"
)

func TestEncoder(t *testing.T) {
	e := &Encoder{
		Version: V2_3,
		Format:  JSON,
		Creators: []Creator{
			{
				Creator:     "Claircore",
				CreatorType: "Tool",
			},
			{
				Creator:     "Clair",
				CreatorType: "Organization",
			},
		},
		// TODO: make this more like a namespace
		DocumentNamespace: "Test SPDX encoder namespace",
		DocumentComment:   "Test SPDX encoder comment",
	}

	ctx := context.Background()
	td := os.DirFS("testdata")
	de, err := fs.ReadDir(td, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range de {
		n := de.Name()
		if strings.HasSuffix(n, ".want.json") {
			continue
		}
		t.Run(n, func(t *testing.T) {
			f, err := td.Open(n)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			ext := path.Ext(n)
			base := strings.TrimSuffix(n, ext)
			wantPath := fmt.Sprintf("%s.want%s", base, ext)
			w, err := td.Open(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()

			var want map[string]interface{}
			if err := json.NewDecoder(w).Decode(&want); err != nil {
				t.Error(err)
			}

			var ir claircore.IndexReport
			if err := json.NewDecoder(f).Decode(&ir); err != nil {
				t.Error(err)
			}
			r, err := e.Encode(ctx, &ir)
			var got map[string]interface{}
			if err := json.NewDecoder(r).Decode(&got); err != nil {
				t.Error(err)
			}

			if !cmp.Equal(want, got) {
				t.Error(cmp.Diff(got, want))
			}
		})
	}
}
