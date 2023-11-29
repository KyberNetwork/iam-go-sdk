package cache

import "errors"

var (
	ErrNil          = errors.New("cache error: nil")
	ErrMismatchType = errors.New("cache error: mismatch type")
)
