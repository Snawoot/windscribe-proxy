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

type SessionResponse struct {
	Data *struct {
		SessionAuthHash  string  `json:"session_auth_hash"`
		Username         string  `json:"username"`
		UserID           string  `json:"user_id"`
		TrafficUsed      float64 `json:"traffic_used"`
		TrafficMax       float64 `json:"traffic_max"`
		Status           int     `json:"status"`
		Email            *string `json:"email"`
		EmailStatus      int     `json:"email_status"`
		BillingPlanID    int64   `json:"billing_plan_id"`
		IsPremium        int     `json:"is_premium"`
		RegDate          float64 `json:"reg_date"`
		LocationRevision int     `json:"loc_rev"`
		LocationHash     string  `json:"loc_hash"`
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

type ServerListResponse struct {
	Data ServerList `json:"data"`
	Info *struct {
		Revision       int    `json:"revision"`
		RevisionHash   string `json:"revision_hash"`
		Changed        int    `json:"changed"`
		FC             int    `json:"fc"`
		ProDatacenters []interface{}
	} `json:"info"`
}

type ServerList []ServerListLocation

type ServerListLocation struct {
	ID           int               `json:"id"`
	Name         string            `json:"name"`
	CountryCode  string            `json:"country_code"`
	Status       int               `json:"status"`
	PremiumOnly  int               `json:"premium_only"`
	ShortName    string            `json:"short_name"`
	P2P          int               `json:"p2p"`
	TZName       string            `json:"tz"`
	TZOffset     string            `json:"tz_offset"`
	LocationType string            `json:"loc_type"`
	ForceExpand  int               `json:"force_expand"`
	Groups       []ServerListGroup `json:"groups"`
}

type ServerListGroup struct {
	ID       int                   `json:"id"`
	City     string                `json:"city"`
	Nick     string                `json:"nick"`
	Pro      int                   `json:"pro"`
	GPS      string                `json:"gps"`
	WGPubkey []byte                `json:"wg_pubkey"`
	PingIP   string                `json:"ping_ip"`
	Hosts    []ServerListGroupHost `json:"hosts"`
}

type ServerListGroupHost struct {
	Hostname string  `json:"hostname"`
	Weight   float64 `json:"weight"`
}

type BestLocation struct {
	CountryCode  string `json:"country_code"`
	ShortName    string `json:"short_name"`
	LocationName string `json:"location_name"`
	CityName     string `json:"city_name"`
	DCID         int    `json:"dc_id"`
	ServerID     int    `json:"server_id"`
	Hostname     string `json:"hostname"`
}

type BestLocationResponse struct {
	Data *BestLocation `json:"data"`
}
