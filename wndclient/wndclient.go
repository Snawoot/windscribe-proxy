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
	"net/url"
	"path"
	"strconv"
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

var ErrNoDataInResponse = errors.New("no \"data\" key in response")

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

type WndClientState struct {
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
	ProxyUsername      string
	ProxyPassword      string
	Settings           WndSettings
}

type WndClient struct {
	httpClient         *http.Client
	Mux                sync.Mutex
	State              WndClientState
}

type StrKV map[string]string

func NewWndClient(transport http.RoundTripper) (*WndClient, error) {
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &WndClient{
		httpClient: &http.Client{
			Transport: transport,
		},
		State: WndClientState{
			Settings: DefaultWndSettings,
		},
	}, nil
}

func (c *WndClient) RegisterToken(ctx context.Context) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.State.Settings.ClientAuthSecret)
	input := RegisterTokenRequest{
		ClientAuthHash: clientAuthHash,
		Time:           authTime,
	}

	var output RegisterTokenResponse

	err := c.postJSON(ctx, c.State.Settings.Endpoints.RegisterToken, input, &output)
	if err != nil {
		return err
	}
	if output.Data == nil {
		return ErrNoDataInResponse
	}

	c.State.TokenID = output.Data.TokenID
	c.State.Token = output.Data.Token
	c.State.TokenSignature = output.Data.TokenSignature
	c.State.TokenSignatureTime = output.Data.TokenTime

	return nil
}

func (c *WndClient) Users(ctx context.Context) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.State.Settings.ClientAuthSecret)
	input := UsersRequest{
		ClientAuthHash: clientAuthHash,
		Time:           authTime,
		SessionType:    SESSION_TYPE_EXT,
		Token:          c.State.Token,
	}

	var output UsersResponse

	err := c.postJSON(ctx, c.State.Settings.Endpoints.Users, input, &output)
	if err != nil {
		return err
	}
	if output.Data == nil {
		return ErrNoDataInResponse
	}

	c.State.UserID = output.Data.UserID
	c.State.SessionAuthHash = output.Data.SessionAuthHash
	c.State.Status = output.Data.Status
	c.State.IsPremium = output.Data.IsPremium != 0
	c.State.LocationRevision = output.Data.LocationRevision
	c.State.LocationHash = output.Data.LocationHash

	return nil
}

func (c *WndClient) ServerCredentials(ctx context.Context) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.State.Settings.ClientAuthSecret)

	requestUrl, err := url.Parse(c.State.Settings.Endpoints.ServerCredentials)
	if err != nil {
		return err
	}
	queryValues := requestUrl.Query()
	queryValues.Set("client_auth_hash", clientAuthHash)
	queryValues.Set("session_auth_hash", c.State.SessionAuthHash)
	queryValues.Set("time", strconv.FormatInt(authTime, 10))
	requestUrl.RawQuery = queryValues.Encode()

	var output ServerCredentialsResponse

	err = c.getJSON(ctx, requestUrl.String(), &output)
	if err != nil {
		return err
	}
	if output.Data == nil {
		return ErrNoDataInResponse
	}

	c.State.ProxyUsername = string(output.Data.Username)
	c.State.ProxyPassword = string(output.Data.Password)

	return nil
}

func (c *WndClient) ServerList(ctx context.Context) (ServerList, error) {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	requestUrl, err := url.Parse(c.State.Settings.Endpoints.ServerList)
	if err != nil {
		return nil, err
	}
	isPremium := "0"
	if c.State.IsPremium {
		isPremium = "1"
	}
	requestUrl.Path = path.Join(requestUrl.Path, c.State.Settings.Type, isPremium, c.State.LocationHash)

	var output ServerListResponse

	err = c.getJSON(ctx, requestUrl.String(), &output)
	if err != nil {
		return nil, err
	}
	if output.Data == nil {
		return nil, ErrNoDataInResponse
	}

	return output.Data, nil
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

func (c *WndClient) GetProxyCredentials() (string, string) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return c.State.ProxyUsername, c.State.ProxyPassword
}

func (c *WndClient) getJSON(ctx context.Context, requestUrl string, output interface{}) error {
	req, err := http.NewRequestWithContext(
		ctx,
		"GET",
		requestUrl,
		nil,
	)
	if err != nil {
		return err
	}

	c.populateRequest(req)
	req.Header.Set("Accept", "*/*")

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
	req.Header.Set("User-Agent", c.State.Settings.UserAgent)
	req.Header.Set("Origin", c.State.Settings.Origin)
	queryValues := req.URL.Query()
	queryValues.Set("platform", c.State.Settings.Platform)
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
