package cert

import (
	"bytes"
)

func MockPrintTarget() (*bytes.Buffer, func()) {
	bak := out
	mock := new(bytes.Buffer)
	out = mock
	return mock, func() {
		out = bak
	}
}
