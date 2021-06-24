package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	//"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	//"strings"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/Snawoot/windscribe-proxy/wndclient"
)

const (
	DEFAULT_CLIENT_AUTH_SECRET = "952b4412f002315aa50751032fcaab03"
	ASSUMED_PROXY_PORT         = 443
)

var (
	version = "undefined"
)

func perror(msg string) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
	perror(msg)
	perror("Usage:")
	flag.PrintDefaults()
	os.Exit(2)
}

type CLIArgs struct {
	country          string
	listCountries    bool
	listProxies      bool
	bindAddress      string
	verbosity        int
	timeout          time.Duration
	showVersion      bool
	proxy            string
	bootstrapDNS     string
	refresh          time.Duration
	refreshRetry     time.Duration
	caFile           string
	clientAuthSecret string
	stateFile        string
}

func parse_args() CLIArgs {
	var args CLIArgs
	flag.StringVar(&args.country, "country", "EU", "desired proxy location")
	flag.BoolVar(&args.listCountries, "list-countries", false, "list available countries and exit")
	flag.BoolVar(&args.listProxies, "list-proxies", false, "output proxy list and exit")
	flag.StringVar(&args.bindAddress, "bind-address", "127.0.0.1:28080", "HTTP proxy listen address")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.StringVar(&args.proxy, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	flag.StringVar(&args.bootstrapDNS, "bootstrap-dns", "",
		"DNS/DoH/DoT/DoQ resolver for initial discovering of SurfEasy API address. "+
			"See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. "+
			"Examples: https://1.1.1.1/dns-query, quic://dns.adguard.com")
	flag.DurationVar(&args.refresh, "refresh", 4*time.Hour, "login refresh interval")
	flag.DurationVar(&args.refreshRetry, "refresh-retry", 5*time.Second, "login refresh retry interval")
	flag.StringVar(&args.caFile, "cafile", "", "use custom CA certificate bundle file")
	flag.StringVar(&args.clientAuthSecret, "auth-secret", DEFAULT_CLIENT_AUTH_SECRET, "client auth secret")
	flag.StringVar(&args.stateFile, "state-file", "wndstate.json", "file name used to persist "+
		"Windscribe API client state")
	flag.Parse()
	if args.country == "" {
		arg_fail("Country can't be empty string.")
	}
	if args.listCountries && args.listProxies {
		arg_fail("list-countries and list-proxies flags are mutually exclusive")
	}
	return args
}

func proxyFromURLWrapper(u *url.URL, next xproxy.Dialer) (xproxy.Dialer, error) {
	cdialer, ok := next.(ContextDialer)
	if !ok {
		return nil, errors.New("only context dialers are accepted")
	}

	return ProxyDialerFromURL(u, cdialer)
}

func run() int {
	args := parse_args()
	if args.showVersion {
		fmt.Println(version)
		return 0
	}

	logWriter := NewLogWriter(os.Stderr)
	defer logWriter.Close()

	mainLogger := NewCondLogger(log.New(logWriter, "MAIN    : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)
	proxyLogger := NewCondLogger(log.New(logWriter, "PROXY   : ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	mainLogger.Info("windscribe-proxy client version %s is starting...", version)

	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	if args.proxy != "" {
		xproxy.RegisterDialerType("http", proxyFromURLWrapper)
		xproxy.RegisterDialerType("https", proxyFromURLWrapper)
		proxyURL, err := url.Parse(args.proxy)
		if err != nil {
			mainLogger.Critical("Unable to parse base proxy URL: %v", err)
			return 6
		}
		pxDialer, err := xproxy.FromURL(proxyURL, dialer)
		if err != nil {
			mainLogger.Critical("Unable to instantiate base proxy dialer: %v", err)
			return 7
		}
		dialer = pxDialer.(ContextDialer)
	}

	wndclientDialer := dialer

	// Dialing w/o SNI, receiving self-signed certificate, so skip verification.
	// Either way we'll validate certificate of actual proxy server.
	tlsConfig := &tls.Config{
		ServerName:         "",
		InsecureSkipVerify: true,
	}
	wndclient, err := wndclient.NewWndClient(&http.Transport{
		DialContext: wndclientDialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := wndclientDialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, tlsConfig), nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	})
	if err != nil {
		mainLogger.Critical("Unable to construct WndClient: %v", err)
		return 8
	}

	// Try ressurect state
	state, err := loadState(args.stateFile)
	if err != nil {
		mainLogger.Warning("Failed to load client state: %v. Performing cold init...", err)
		err = coldInit(wndclient, args.timeout)
		if err != nil {
			mainLogger.Critical("Cold init failed: %v", err)
			return 9
		}
	} else {
		wndclient.State = *state
	}

	//ctx, cl = context.WithTimeout(context.Background(), args.timeout)
	//ips, err := wndclient.Discover(ctx, fmt.Sprintf("\"%s\",,", args.country))
	//if err != nil {
	//	mainLogger.Critical("Endpoint discovery failed: %v", err)
	//	return 12
	//}

	//if len(ips) == 0 {
	//	mainLogger.Critical("Empty endpoint list!")
	//	return 13
	//}

	//runTicker(context.Background(), args.refresh, args.refreshRetry, func(ctx context.Context) error {
	//	mainLogger.Info("Refreshing login...")
	//	reqCtx, cl := context.WithTimeout(ctx, args.timeout)
	//	defer cl()
	//	err := wndclient.Login(reqCtx)
	//	if err != nil {
	//		mainLogger.Error("Login refresh failed: %v", err)
	//		return err
	//	}
	//	mainLogger.Info("Login refreshed.")

	//	mainLogger.Info("Refreshing device password...")
	//	reqCtx, cl = context.WithTimeout(ctx, args.timeout)
	//	defer cl()
	//	err = wndclient.DeviceGeneratePassword(reqCtx)
	//	if err != nil {
	//		mainLogger.Error("Device password refresh failed: %v", err)
	//		return err
	//	}
	//	mainLogger.Info("Device password refreshed.")
	//	return nil
	//})

	//endpoint := ips[0]
	auth := func() string {
		return basic_auth_header(wndclient.GetProxyCredentials())
	}

	var caPool *x509.CertPool
	if args.caFile != "" {
		caPool = x509.NewCertPool()
		certs, err := ioutil.ReadFile(args.caFile)
		if err != nil {
			mainLogger.Error("Can't load CA file: %v", err)
			return 15
		}
		if ok := caPool.AppendCertsFromPEM(certs); !ok {
			mainLogger.Error("Can't load certificates from CA file")
			return 15
		}
	}

	// TODO: set servername
	//handlerDialer := NewProxyDialer(endpoint.NetAddr(), "", auth, caPool, dialer)
	//mainLogger.Info("Endpoint: %s", endpoint.NetAddr())
	//mainLogger.Info("Starting proxy server...")
	//handler := NewProxyHandler(handlerDialer, proxyLogger)
	//mainLogger.Info("Init complete.")
	//err = http.ListenAndServe(args.bindAddress, handler)
	//mainLogger.Critical("Server terminated with a reason: %v", err)
	//mainLogger.Info("Shutting down...")
	_ = proxyLogger
	_ = auth
	return 0
}

func printProxies(wndclient *wndclient.WndClient) int {
	//wr := csv.NewWriter(os.Stdout)
	//defer wr.Flush()
	//login, password := wndclient.GetProxyCredentials()
	//fmt.Println("Proxy login:", login)
	//fmt.Println("Proxy password:", password)
	//fmt.Println("Proxy-Authorization:", basic_auth_header(login, password))
	//fmt.Println("")
	//wr.Write([]string{"host", "ip_address", "port"})
	//for i, ip := range ips {
	//	for _, port := range ip.Ports {
	//		wr.Write([]string{
	//			fmt.Sprintf("%s%d.%s", strings.ToLower(ip.Geo.CountryCode), i, PROXY_SUFFIX),
	//			ip.IP,
	//			fmt.Sprintf("%d", port),
	//		})
	//	}
	//}
	return 0
}

func loadState(filename string) (*wndclient.WndClientState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var state wndclient.WndClientState
	dec := json.NewDecoder(file)
	err = dec.Decode(&state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func saveState(filename string, state *wndclient.WndClientState) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	err = enc.Encode(state)
	return err
}

func coldInit(wndclient *wndclient.WndClient, timeout time.Duration) error {
	ctx, cl := context.WithTimeout(context.Background(), timeout)
	err := wndclient.RegisterToken(ctx)
	if err != nil {
		return err
	}
	cl()

	ctx, cl = context.WithTimeout(context.Background(), timeout)
	err = wndclient.Users(ctx)
	cl()

	return err
}

func main() {
	os.Exit(run())
}
