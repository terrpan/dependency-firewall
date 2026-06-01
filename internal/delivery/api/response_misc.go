package api

type cacheClearResponse struct {
	Status string `json:"status"`
	Cache  string `json:"cache"`
}

type policyImportResponse struct {
	Imported int `json:"imported"`
}
