package wndclient

const (
	READ_LIMIT                int64 = 128 * 1024
	SESSION_TYPE_WEB                = 1
	SESSION_TYPE_EXT                = 2
	SESSION_TYPE_DESKTOP            = 3
	SESSION_TYPE_MOBILE             = 4
	ACCOUNT_STATE_ACTIVE            = 1
	ACCOUNT_STATE_OUT_OF_DATA       = 2
	ACCOUNT_STATE_BANNED            = 3
)

type WndEndpoints struct {
	RegisterToken     string
	Users             string
	ServerList        string
	ServerCredentials string
}

var DefaultWndEndpoints = WndEndpoints{
	RegisterToken:     "https://api.windscribe.com/RegToken",
	Users:             "https://api.windscribe.com/Users",
	ServerList:        "https://assets.windscribe.com/serverlist",
	ServerCredentials: "https://api.windscribe.com/ServerCredentials",
}

type WndSettings struct {
	Platform    string
	Type        string
	UserAgent   string
	Origin      string
	SessionType int
	Endpoints   WndEndpoints
}

var DefaultWndSettings = WndSettings{
	Platform:    "chrome",
	Type:        "chrome",
	UserAgent:   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
	Origin:      "chrome-extension://hnmpcagpplmpfojmgmnngilcnanddlhb",
	SessionType: SESSION_TYPE_EXT,
	Endpoints:   DefaultWndEndpoints,
}

type WndClient struct {
	httpClient       *http.Client
	Settings         WndSettings
	TokenID          string
	Token            string
	Signature        string
	SignatureTime    int64
	LocationHash     string
	LocationRevision int
	IsPremium        bool
	Status           int
	UserID           string
	SessionAuthHash  string
}
