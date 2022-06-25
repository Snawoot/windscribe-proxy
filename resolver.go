package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/jellydator/ttlcache/v2"
	"github.com/miekg/dns"
)

type Resolver struct {
	upstream upstream.Upstream
}

const (
	DOT                  = 0x2e
	DNS_CACHE_SIZE_LIMIT = 1024
)

type ResolvingDialer struct {
	next     ContextDialer
	upstream upstream.Upstream
	cache4   *ttlcache.Cache
	cache6   *ttlcache.Cache
	logger   *CondLogger
}

func NewResolvingDialer(resolverAddress string, timeout time.Duration, next ContextDialer, logger *CondLogger) (*ResolvingDialer, error) {
	opts := &upstream.Options{Timeout: timeout}
	u, err := upstream.AddressToUpstream(resolverAddress, opts)
	if err != nil {
		return nil, err
	}
	cache4 := ttlcache.NewCache()
	cache6 := ttlcache.NewCache()
	d := &ResolvingDialer{
		upstream: u,
		next:     next,
		cache4:   cache4,
		cache6:   cache6,
		logger:   logger,
	}
	cache4.SetLoaderFunction(d.resolveA)
	cache6.SetLoaderFunction(d.resolveAAAA)
	cache4.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache6.SetCacheSizeLimit(DNS_CACHE_SIZE_LIMIT)
	cache4.SkipTTLExtensionOnHit(true)
	cache6.SkipTTLExtensionOnHit(true)

	return d, nil
}

func (d *ResolvingDialer) resolveA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveA(%#v)", domain)
	return d.resolve(domain, dns.TypeA)
}

func (d *ResolvingDialer) resolveAAAA(domain string) (interface{}, time.Duration, error) {
	d.logger.Debug("resolveAAAA(%#v)", domain)
	return d.resolve(domain, dns.TypeAAAA)
}

func (d *ResolvingDialer) resolve(domain string, typ uint16) (string, time.Duration, error) {
	if len(domain) == 0 {
		return "", 0, errors.New("empty domain name")
	}
	domain = absDomain(domain)

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: domain, Qtype: typ, Qclass: dns.ClassINET},
	}
	reply, err := d.upstream.Exchange(&req)
	if err != nil {
		return "", 0, err
	}
	for _, rr := range reply.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), (time.Second * time.Duration(a.Hdr.Ttl)), nil
		}
	}
	return "", 0, errors.New("no data in DNS response")
}

func (d *ResolvingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if net.ParseIP(name) != nil || len(name) == 0 {
		// Address is already in numeric form
		return d.next.DialContext(ctx, network, address)
	}

	if len(network) == 0 {
		return d.next.DialContext(ctx, network, address)
	}

	name = absDomain(name)
	switch network[len(network)-1] {
	case '4':
		res, err := d.cache4.Get(name)
		if err != nil {
			return nil, err
		}
		name = res.(string)
	case '6':
		res, err := d.cache6.Get(name)
		if err != nil {
			return nil, err
		}
		name = res.(string)
	default:
		res, err := d.cache4.Get(name)
		if err != nil {
			res, err = d.cache6.Get(name)
			if err != nil {
				return nil, err
			}
		}
		name = res.(string)
	}
	newAddress := net.JoinHostPort(name, port)
	d.logger.Debug("resolve rewrite: %s => %s", address, newAddress)
	return d.next.DialContext(ctx, network, newAddress)
}

func (d *ResolvingDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func absDomain(domain string) string {
	if domain == "" {
		return ""
	}
	if domain[len(domain)-1] != DOT {
		domain = domain + "."
	}
	return strings.ToLower(domain)
}
