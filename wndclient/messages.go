package wndclient

type WndRegisterTokenRequest struct {
	ClientAuthHash string `json:"client_auth_hash"`
	Time           int64  `json:"time,string"`
}

type WndRegisterTokenResponse struct {
	TokenID        string `json:"id"`
	Token          string `json:"token"`
	TokenSignature string `json:"signature"`
	TokenTime      int64  `json:"time,string"`
}
