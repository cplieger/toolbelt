package toolbelt

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func manifestSeeds(f *testing.F) {
	f.Add([]byte(`{"version":2,"tools":{"jq":{"source":"aqua:jqlang/jq","version":"1.8.1"}}}`))
	f.Add([]byte("\xef\xbb\xbf{\"version\":2,\"tools\":{}}\n"))
	f.Add([]byte(`{"version":2,"tools":{`))
	f.Add([]byte(`{"version":1,"tools":{}}`))
	f.Add([]byte(`{"version":2,"tools":{"..":{"source":"manual"}}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
}

// A replace the engine accepts is on disk byte for byte and reads back as
// ParseManifest reads it; a refused one leaves the file as it was.
func FuzzReplaceManifest_verbatim(f *testing.F) {
	manifestSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		e := newTestEngine(t, nil)
		orig := readManifestFile(t, e)
		want, perr := ParseManifest(data)
		err := e.ReplaceManifest(data, nil)
		if (err == nil) != (perr == nil) {
			t.Fatalf("ReplaceManifest(%q) = %v, ParseManifest = %v; want the same verdict", data, err, perr)
		}
		got := readManifestFile(t, e)
		if err != nil {
			if !bytes.Equal(got, orig) {
				t.Fatalf("a refused ReplaceManifest(%q) changed tools.json to %q", data, got)
			}
			return
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("tools.json = %q, want %q verbatim", got, data)
		}
		m, err := e.store.LoadManifest()
		if err != nil || sortedToolNames(m) != sortedToolNames(want) {
			t.Fatalf("LoadManifest after ReplaceManifest(%q) = %v, %v; want %v", data, m, err, want)
		}
	})
}

// WriteManifest writes exactly what ParseManifest accepts, verbatim, and
// nothing else.
func FuzzWriteManifest_verbatim(f *testing.F) {
	manifestSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		_, perr := ParseManifest(data)
		err := WriteManifest(dir, data)
		if (err == nil) != (perr == nil) {
			t.Fatalf("WriteManifest(%q) = %v, ParseManifest = %v; want the same verdict", data, err, perr)
		}
		got, rerr := os.ReadFile(filepath.Join(dir, manifestFile))
		if err != nil {
			if !os.IsNotExist(rerr) {
				t.Fatalf("a refused WriteManifest(%q) left tools.json: %q, %v", data, got, rerr)
			}
			return
		}
		if rerr != nil || !bytes.Equal(got, data) {
			t.Fatalf("tools.json = %q, %v; want %q verbatim", got, rerr, data)
		}
	})
}
