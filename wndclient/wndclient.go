package wndclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	//"net/url"
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

var ErrNoDataInResponse = errors.New("no \"data\" key in response")

type WndClient struct {
	httpClient         *http.Client
	Settings           WndSettings
	TokenID            string
	Token              string
	TokenSignature     string
	TokenSignatureTime int64
	LocationHash       string
	LocationRevision   int
	IsPremium          bool
	Status             int
	UserID             string
	SessionAuthHash    string
	Mux                sync.Mutex
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

	return &WndClient{
		httpClient: &http.Client{
			Jar:       jar,
			Transport: transport,
		},
		Settings: DefaultWndSettings,
	}, nil
}

func (c *WndClient) ResetCookies() error {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return c.resetCookies()
}

func (c *WndClient) resetCookies() error {
	return (c.httpClient.Jar.(*StdJar)).Reset()
}

func (c *WndClient) RegisterToken(ctx context.Context) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.Settings.ClientAuthSecret)
	input := RegisterTokenRequest{
		ClientAuthHash: clientAuthHash,
		Time:           authTime,
	}

	var output RegisterTokenResponse

	err := c.postJSON(ctx, c.Settings.Endpoints.RegisterToken, input, &output)
	if err != nil {
		return err
	}
	if output.Data == nil {
		return ErrNoDataInResponse
	}

	c.TokenID = output.Data.TokenID
	c.Token = output.Data.Token
	c.TokenSignature = output.Data.TokenSignature
	c.TokenSignatureTime = output.Data.TokenTime

	return nil
}

func (c *WndClient) Users(ctx context.Context) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.Settings.ClientAuthSecret)
	input := UsersRequest{
		ClientAuthHash: clientAuthHash,
		Time:           authTime,
		SessionType:    SESSION_TYPE_EXT,
		Token:          c.Token,
	}

	var output UsersResponse

	err := c.postJSON(ctx, c.Settings.Endpoints.Users, input, &output)
	if err != nil {
		return err
	}
	if output.Data == nil {
		return ErrNoDataInResponse
	}

	c.UserID = output.Data.UserID
	c.SessionAuthHash = output.Data.SessionAuthHash
	c.Status = output.Data.Status
	c.IsPremium = output.Data.IsPremium != 0
	c.LocationRevision = output.Data.LocationRevision
	c.LocationHash = output.Data.LocationHash

	return nil
}

func (c *WndClient) postJSON(ctx context.Context, endpoint string, input, output interface{}) error {
	var reqBuf bytes.Buffer
	reqEncoder := json.NewEncoder(&reqBuf)
	err := reqEncoder.Encode(input)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		endpoint,
		&reqBuf,
	)
	if err != nil {
		return err
	}

	c.populateRequest(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("bad http status: %s, headers: %#v", resp.Status, resp.Header)
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(output)
	cleanupBody(resp.Body)

	if err != nil {
		return err
	}

	return nil
}

func (c *WndClient) populateRequest(req *http.Request) {
	req.Header.Set("User-Agent", c.Settings.UserAgent)
	req.Header.Set("Origin", c.Settings.Origin)
	queryValues := req.URL.Query()
	queryValues.Set("platform", c.Settings.Platform)
	req.URL.RawQuery = queryValues.Encode()
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
