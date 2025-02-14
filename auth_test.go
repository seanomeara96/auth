package auth

import (
	"testing"
)

func TestNewErr(t *testing.T) {
	err := newErr(internalErr, "error")
	if err == nil {
		t.Error(err)
	}
	if err.t != internalErr {
		t.Error("expected an internal error")
	}
}

//
