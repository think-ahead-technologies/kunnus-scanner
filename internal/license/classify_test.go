// ABOUTME: Tests the full-text license classifier (the probabilistic fallback to Normalize).
// ABOUTME: Confirms recognisable licence text resolves to SPDX and that prose / empty input yields nothing.
package license

import (
	"reflect"
	"testing"
)

const mitText = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

func TestClassify_RecognisesLicenseText(t *testing.T) {
	got := Classify([]byte(mitText))
	if !reflect.DeepEqual(got, []string{"MIT"}) {
		t.Errorf("Classify(MIT text) = %v, want [MIT]", got)
	}
}

func TestClassify_PreambleThenLicenseText(t *testing.T) {
	// A Debian-style copyright: prose header followed by the licence text. The
	// classifier should still find the licence among the prose.
	doc := "This is the Debian packaged version of foo.\nIt was downloaded from example.com.\n\n" + mitText
	got := Classify([]byte(doc))
	found := false
	for _, id := range got {
		if id == "MIT" {
			found = true
		}
	}
	if !found {
		t.Errorf("Classify(preamble+MIT) = %v, want it to include MIT", got)
	}
}

func TestClassify_NoLicenseText(t *testing.T) {
	prose := "This package was debianized by someone. The upstream source is at example.com."
	if got := Classify([]byte(prose)); len(got) != 0 {
		t.Errorf("Classify(prose) = %v, want empty", got)
	}
	if got := Classify(nil); len(got) != 0 {
		t.Errorf("Classify(nil) = %v, want empty", got)
	}
}
