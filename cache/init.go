package cache

func init() {
	if cacheMap == nil {
		cacheMap = make(map[string]interface{})
	}
}
