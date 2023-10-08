package main

import (
	"context"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/Snawoot/windscribe-proxy/wndclient"
)

const (
	DEFAULT_CLIENT_AUTH_SECRET        = "952b4412f002315aa50751032fcaab03"
	ASSUMED_PROXY_PORT         uint16 = 443
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
	location         string
	listLocations    bool
	listProxies      bool
	bindAddress      string
	verbosity        int
	timeout          time.Duration
	showVersion      bool
	proxy            string
	resolver         string
	caFile           string
	clientAuthSecret string
	stateFile        string
	username         string
	password         string
	tfacode          string
	fakeSNI          string
	forceColdInit    bool
}

func parse_args() CLIArgs {
	var args CLIArgs
	flag.StringVar(&args.location, "location", "", "desired proxy location. Default: best location")
	flag.BoolVar(&args.listLocations, "list-locations", false, "list available locations and exit")
	flag.BoolVar(&args.listProxies, "list-proxies", false, "output proxy list and exit")
	flag.StringVar(&args.bindAddress, "bind-address", "127.0.0.1:28080", "HTTP proxy listen address")
	flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity "+
		"(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
	flag.DurationVar(&args.timeout, "timeout", 10*time.Second, "timeout for network operations")
	flag.BoolVar(&args.showVersion, "version", false, "show program version and exit")
	flag.StringVar(&args.proxy, "proxy", "", "sets base proxy to use for all dial-outs. "+
		"Format: <http|https|socks5|socks5h>://[login:password@]host[:port] "+
		"Examples: http://user:password@192.168.1.1:3128, socks5://10.0.0.1:1080")
	// TODO: implement DNS resolving or remove it
	flag.StringVar(&args.resolver, "resolver", "",
		"Use DNS/DoH/DoT/DoQ resolver for all dial-outs. "+
			"See https://github.com/ameshkov/dnslookup/ for upstream DNS URL format. "+
			"Examples: https://1.1.1.1/dns-query, quic://dns.adguard.com")
	flag.StringVar(&args.caFile, "cafile", "", "use custom CA certificate bundle file")
	flag.StringVar(&args.clientAuthSecret, "auth-secret", DEFAULT_CLIENT_AUTH_SECRET, "client auth secret")
	flag.StringVar(&args.stateFile, "state-file", "wndstate.json", "file name used to persist "+
		"Windscribe API client state")
	flag.StringVar(&args.username, "username", "", "username for login")
	flag.StringVar(&args.password, "password", "", "password for login")
	flag.StringVar(&args.tfacode, "2fa", "", "2FA code for login")
	flag.StringVar(&args.fakeSNI, "fake-sni", "com", "fake SNI to use to contact windscribe servers")
	flag.BoolVar(&args.forceColdInit, "force-cold-init", false, "force cold init")
	flag.Parse()
	if args.listLocations && args.listProxies {
		arg_fail("list-locations and list-proxies flags are mutually exclusive")
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
	var err error
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
	resolverLogger := NewCondLogger(log.New(logWriter, "RESOLVER: ",
		log.LstdFlags|log.Lshortfile),
		args.verbosity)

	mainLogger.Info("windscribe-proxy client version %s is starting...", version)

	var dialer ContextDialer = &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
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

	if args.resolver != "" {
		dialer, err = NewResolvingDialer(args.resolver, args.timeout, dialer, resolverLogger)
		if err != nil {
			mainLogger.Critical("Unable to instantiate resolver: %v", err)
			return 5
		}
	}

	wndclientDialer := dialer

	wndc, err := wndclient.NewWndClient(&http.Transport{
		DialContext:           wndclientDialer.DialContext,
		DialTLSContext:        NewFakeSNIDialer(caPool, args.fakeSNI, wndclientDialer).DialTLSContext,
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
	wndc.Mux.Lock()
	wndc.State.Settings.ClientAuthSecret = args.clientAuthSecret
	wndc.Mux.Unlock()

	// Try to resurrect state
	state, err := maybeLoadState(args.forceColdInit, args.stateFile)
	if err != nil {
		switch err {
		case errColdInitForced:
			mainLogger.Info("Cold init forced.")
		default:
			mainLogger.Warning("Failed to load client state: %v. It is OK for a first run. Performing cold init...", err)
		}
		err = coldInit(wndc, args.username, args.password, args.tfacode, args.timeout)
		if err != nil {
			mainLogger.Critical("Cold init failed: %v", err)
			return 9
		}
		err = saveState(args.stateFile, &wndc.State)
		if err != nil {
			mainLogger.Error("Unable to save state file! Error: %v", err)
		}
	} else {
		wndc.Mux.Lock()
		wndc.State = *state
		wndc.Mux.Unlock()
	}

	var serverList wndclient.ServerList
	if args.listProxies || args.listLocations || args.location != "" {
		ctx, cl := context.WithTimeout(context.Background(), args.timeout)
		serverList, err = wndc.ServerList(ctx)
		cl()
		if err != nil {
			mainLogger.Critical("Server list retrieve failed: %v", err)
			return 12
		}
	}

	if args.listProxies {
		username, password := wndc.GetProxyCredentials()
		return printProxies(username, password, serverList)
	}

	if args.listLocations {
		return printLocations(serverList)
	}

	var proxyHostname string
	if args.location == "" {
		ctx, cl := context.WithTimeout(context.Background(), args.timeout)
		bestLocation, err := wndc.BestLocation(ctx)
		cl()
		if err != nil {
			mainLogger.Critical("Unable to get best location endpoint: %v", err)
			return 13
		}
		proxyHostname = bestLocation.Hostname
	} else {
		proxyHostname = pickServer(serverList, args.location)
		if proxyHostname == "" {
			mainLogger.Critical("Server for location \"%s\" not found.", args.location)
			return 13
		}
	}

	auth := func() string {
		return basic_auth_header(wndc.GetProxyCredentials())
	}

	proxyNetAddr := net.JoinHostPort(proxyHostname, strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10))
	handlerDialer := NewProxyDialer(proxyNetAddr, proxyHostname, args.fakeSNI, auth, caPool, dialer)
	mainLogger.Info("Endpoint: %s", proxyNetAddr)
	mainLogger.Info("Starting proxy server...")
	handler := NewProxyHandler(handlerDialer, proxyLogger)
	mainLogger.Info("Init complete.")
	err = http.ListenAndServe(args.bindAddress, handler)
	mainLogger.Critical("Server terminated with a reason: %v", err)
	mainLogger.Info("Shutting down...")
	return 0
}

type locationPair struct {
	country string
	city    string
}

func printLocations(serverList wndclient.ServerList) int {
	var locs []locationPair
	for _, country := range serverList {
		for _, group := range country.Groups {
			if len(group.Hosts) > 1 {
				locs = append(locs, locationPair{country.Name, group.City})
			}
		}
	}
	if len(locs) == 0 {
		return 0
	}

	sort.Slice(locs, func(i, j int) bool {
		if locs[i].country < locs[j].country {
			return true
		}
		if locs[i].country == locs[j].country && locs[i].city < locs[j].city {
			return true
		}
		return false
	})

	var prevLoc locationPair
	for _, loc := range locs {
		if loc != prevLoc {
			fmt.Println(loc.country + "/" + loc.city)
			prevLoc = loc
		}
	}
	return 0
}

func printProxies(username, password string, serverList wndclient.ServerList) int {
	wr := csv.NewWriter(os.Stdout)
	defer wr.Flush()
	fmt.Println("Proxy login:", username)
	fmt.Println("Proxy password:", password)
	fmt.Println("Proxy-Authorization:", basic_auth_header(username, password))
	fmt.Println("")
	wr.Write([]string{"location", "hostname", "port"})
	for _, country := range serverList {
		for _, group := range country.Groups {
			for _, host := range group.Hosts {
				wr.Write([]string{
					country.Name + "/" + group.City,
					host.Hostname,
					strconv.FormatUint(uint64(ASSUMED_PROXY_PORT), 10),
				})
			}
		}
	}
	return 0
}

func pickServer(serverList wndclient.ServerList, location string) string {
	var candidates []string
	for _, country := range serverList {
		for _, group := range country.Groups {
			for _, host := range group.Hosts {
				if country.Name+"/"+group.City == location {
					candidates = append(candidates, host.Hostname)
				}
			}
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	return candidates[rnd.Intn(len(candidates))]
}

var errColdInitForced = errors.New("cold init forced!")
func maybeLoadState(forceColdInit bool, filename string) (*wndclient.WndClientState, error) {
	if forceColdInit {
		return nil, errColdInitForced
	}
	return loadState(filename)
}

func loadState(filename string) (*wndclient.WndClientState, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

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
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")
	err = enc.Encode(state)
	return err
}

func coldInit(wndc *wndclient.WndClient, username, password, tfacode string, timeout time.Duration) error {
	if username == "" || password == "" {
		return errors.New(`Please provide "-username" and "-password" command line arguments!`)
	}
	ctx, cl := context.WithTimeout(context.Background(), timeout)
	err := wndc.Session(ctx, username, password, tfacode)
	cl()
	if err != nil {
		return fmt.Errorf("Session call failed: %w", err)
	}

	ctx, cl = context.WithTimeout(context.Background(), timeout)
	err = wndc.ServerCredentials(ctx)
	cl()
	if err != nil {
		return fmt.Errorf("ServerCredentials call failed: %w", err)
	}

	return nil
}

func main() {
	os.Exit(run())
}
