package cache

import "sync"

var lock sync.Mutex
var cacheMap map[string]any

func Set(key string, value any) {
	lock.Lock()
	defer lock.Unlock()
	cacheMap[key] = value
}

func Get[T any](key string) (T, error) {
	lock.Lock()
	defer lock.Unlock()

	var nilResult T

	value := cacheMap[key]
	if value == nil {
		return nilResult, ErrNil
	}
	ret, ok := value.(T)
	if !ok {
		return nilResult, ErrMismatchType
	}
	return ret, nil
}
