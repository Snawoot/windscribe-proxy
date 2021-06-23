package wndclient

import (
	//"context"
	//"encoding/json"
	//"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"
)

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
	ClientAuthSecret string
	Platform         string
	Type             string
	UserAgent        string
	Origin           string
	SessionType      int
	Endpoints        WndEndpoints
}

var DefaultWndSettings = WndSettings{
	ClientAuthSecret: "952b4412f002315aa50751032fcaab03",
	Platform:         "chrome",
	Type:             "chrome",
	UserAgent:        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36",
	Origin:           "chrome-extension://hnmpcagpplmpfojmgmnngilcnanddlhb",
	SessionType:      SESSION_TYPE_EXT,
	Endpoints:        DefaultWndEndpoints,
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
	Mux              sync.Mutex
}

type StrKV map[string]string

func NewWndClient(transport http.RoundTripper) (*WndClient, error) {
	if transport == nil {
		transport = http.DefaultTransport
	}

	jar, err := NewStdJar()
	if err != nil {
		return nil, err
	}

	return &SEClient{
		httpClient: &http.Client{
			Jar:       jar,
			Transport: transport,
		},
		Settings: DefaultWndSettings,
	}, nil
}

func (c *SEClient) ResetCookies() error {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return c.resetCookies()
}

func (c *SEClient) resetCookies() error {
	return (c.httpClient.Jar.(*StdJar)).Reset()
}

// Does cleanup of HTTP response in order to make it reusable by keep-alive
// logic of HTTP client
func cleanupBody(body io.ReadCloser) {
	io.Copy(ioutil.Discard, &io.LimitedReader{
		R: body,
		N: READ_LIMIT,
	})
	body.Close()
}
