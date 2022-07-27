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
	"strings"
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
	Session           string `json:"Session"`
	ServerList        string `json:"serverlist"`
	ServerCredentials string `json:"ServerCredentials"`
	BestLocation      string `json:"BestLocation"`
}

var DefaultWndEndpoints = WndEndpoints{
	Session:           "https://api.windscribe.com/Session",
	ServerList:        "https://assets.windscribe.com/serverlist",
	ServerCredentials: "https://api.windscribe.com/ServerCredentials",
	BestLocation:      "https://api.windscribe.com/BestLocation",
}

type WndSettings struct {
	ClientAuthSecret string       `json:"client_auth_secret"`
	Platform         string       `json:"platform"`
	Type             string       `json:"type"`
	UserAgent        string       `json:"user_agent"`
	Origin           string       `json:"origin"`
	SessionType      int          `json:"session_type"`
	Endpoints        WndEndpoints `json:"endpoints"`
}

var DefaultWndSettings = WndSettings{
	ClientAuthSecret: "952b4412f002315aa50751032fcaab03",
	Platform:         "chrome",
	Type:             "chrome",
	UserAgent:        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
	Origin:           "chrome-extension://hnmpcagpplmpfojmgmnngilcnanddlhb",
	SessionType:      SESSION_TYPE_EXT,
	Endpoints:        DefaultWndEndpoints,
}

type WndClientState struct {
	TokenID            string      `json:"token_id"`
	Token              string      `json:"token"`
	TokenSignature     string      `json:"token_signature"`
	TokenSignatureTime int64       `json:"token_signature_time,string"`
	LocationHash       string      `json:"loc_hash"`
	LocationRevision   int         `json:"loc_rev"`
	IsPremium          bool        `json:"is_premium"`
	Status             int         `json:"status"`
	UserID             string      `json:"user_id"`
	SessionAuthHash    string      `json:"session_auth_hash"`
	ProxyUsername      string      `json:"proxy_username"`
	ProxyPassword      string      `json:"proxy_password"`
	Settings           WndSettings `json:"settings"`
}

type WndClient struct {
	httpClient *http.Client
	Mux        sync.Mutex
	State      WndClientState
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

func (c *WndClient) Session(ctx context.Context, username, password, tfacode string) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.State.Settings.ClientAuthSecret)
	input := url.Values{
		"client_auth_hash": []string{clientAuthHash},
		"time":             []string{strconv.FormatInt(authTime, 10)},
		"session_type_id":  []string{strconv.FormatInt(SESSION_TYPE_EXT, 10)},
		"username":         []string{username},
		"password":         []string{password},
	}
	if tfacode != "" {
		input["2fa_code"] = []string{tfacode}
	}

	var output SessionResponse

	err := c.postForm(ctx, c.State.Settings.Endpoints.Session, input, &output)
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

func (c *WndClient) BestLocation(ctx context.Context) (*BestLocation, error) {
	c.Mux.Lock()
	defer c.Mux.Unlock()

	clientAuthHash, authTime := MakeAuthHash(c.State.Settings.ClientAuthSecret)

	requestUrl, err := url.Parse(c.State.Settings.Endpoints.BestLocation)
	if err != nil {
		return nil, err
	}
	queryValues := requestUrl.Query()
	queryValues.Set("client_auth_hash", clientAuthHash)
	queryValues.Set("session_auth_hash", c.State.SessionAuthHash)
	queryValues.Set("time", strconv.FormatInt(authTime, 10))
	requestUrl.RawQuery = queryValues.Encode()

	var output BestLocationResponse

	err = c.getJSON(ctx, requestUrl.String(), &output)
	if err != nil {
		return nil, err
	}
	if output.Data == nil {
		return nil, ErrNoDataInResponse
	}

	return output.Data, nil
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
		errBodyBytes, _ := ioutil.ReadAll(
			&io.LimitedReader{
				R: resp.Body,
				N: 1024,
			})
		defer resp.Body.Close()
		return fmt.Errorf("bad http status: %s, headers: %#v, body: %q",
			resp.Status, resp.Header, string(errBodyBytes))
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(output)
	cleanupBody(resp.Body)

	if err != nil {
		return err
	}

	return nil
}

func (c *WndClient) postForm(ctx context.Context, endpoint string, input url.Values, output interface{}) error {
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		endpoint,
		strings.NewReader(input.Encode()),
	)
	if err != nil {
		return err
	}

	c.populateRequest(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		errBodyBytes, _ := ioutil.ReadAll(
			&io.LimitedReader{
				R: resp.Body,
				N: 1024,
			})
		defer resp.Body.Close()
		return fmt.Errorf("bad http status: %s, headers: %#v, body: %q",
			resp.Status, resp.Header, string(errBodyBytes))
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
		errBodyBytes, _ := ioutil.ReadAll(
			&io.LimitedReader{
				R: resp.Body,
				N: 1024,
			})
		defer resp.Body.Close()
		return fmt.Errorf("bad http status: %s, headers: %#v, body: %q",
			resp.Status, resp.Header, string(errBodyBytes))
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
