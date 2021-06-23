package wndclient

type RegisterTokenRequest struct {
	ClientAuthHash string `json:"client_auth_hash"`
	Time           int64  `json:"time,string"`
}

type RegisterTokenResponse struct {
	Data *struct {
		TokenID        string `json:"id"`
		Token          string `json:"token"`
		TokenSignature string `json:"signature"`
		TokenTime      int64  `json:"time"`
	} `json:"data"`
}

type UsersRequest struct {
	ClientAuthHash string `json:"client_auth_hash"`
	SessionType    int    `json:"session_type_id"`
	Time           int64  `json:"time,string"`
	Token          string `json:"token"`
}

type UsersResponse struct {
	Data *struct {
		UserID           string `json:"user_id"`
		SessionAuthHash  string `json:"session_auth_hash"`
		Status           int    `json:"status"`
		IsPremium        int    `json:"is_premium"`
		LocationRevision int    `json:"loc_rev"`
		LocationHash     string `json:"loc_hash"`
	} `json:"data"`
}

type ServerCredentialsResponse struct {
	Data *struct {
		Username []byte `json:"username"`
		Password []byte `json:"password"`
	} `json:"data"`
}
