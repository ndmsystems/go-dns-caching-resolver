package resolver

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	logApi "github.com/woody-ltd/go/api/log"
)

const (
	oldHostDuration  = 30 * time.Minute
	retryIntervalSec = 10
)

// host ...
type host struct {
	tag      string
	hostName string
	ip4      *ips
	ip6      *ips
	lastTime int64

	// eaFlag - flag means explicitly added host
	eaFlag bool

	dnsClient *dnsClient
	logger    logApi.Logger

	ready  sync.WaitGroup
	stopCh chan struct{}
}

// newHost ...
func newHost(tag string, hName string, eaFlag bool, dnsClient *dnsClient, logger logApi.Logger) *host {
	h := &host{
		tag:       tag,
		hostName:  hName,
		eaFlag:    eaFlag,
		ip4:       newIps(),
		ip6:       newIps(),
		lastTime:  time.Now().Unix(),
		dnsClient: dnsClient,
		logger:    logger,
		stopCh:    make(chan struct{}),
	}

	h.ready.Add(1)
	go h.reloadIPsLoop()

	return h
}

// getNextIP4WithIndex ...
func (h *host) getNextIP4WithIndex() (net.IP, int) {
	h.ready.Wait()
	defer h.updLastTime()
	return h.ip4.getNextIPWithIndex()
}

// getNextIP6WithIndex ...
func (h *host) getNextIP6WithIndex() (net.IP, int) {
	h.ready.Wait()
	defer h.updLastTime()
	return h.ip6.getNextIPWithIndex()
}

// getIPs ...
func (h *host) getIPs() ([]net.IP, []net.IP) {
	h.ready.Wait()
	return h.ip4.getList(), h.ip6.getList()
}

// reloadIPsLoop ...
func (h *host) reloadIPsLoop() {
	ttl := h.reloadIPs()
	h.ready.Done()

	ttlCh := time.After(time.Duration(ttl) * time.Second)
	for {
		select {
		case <-h.stopCh:
			h.logger.Info().Println(h.tag, "Stop resolving host", h.hostName)
			return
		case <-ttlCh:
			ttl = h.reloadIPs()
			ttlCh = time.After(time.Duration(ttl) * time.Second)
		}
	}
}

// reloadIPs ...
func (h *host) reloadIPs() uint32 {
	ip4, ip6, ttl, err := h.dnsClient.lookupHost(context.Background(), h.hostName)
	if err != nil {
		h.logger.Error().Println(h.tag, "Error reloading ips for host", h.hostName, err)
		return retryIntervalSec
	}

	h.ip4.setIpList(ip4)
	h.ip6.setIpList(ip6)

	return ttl
}

// isOld ...
func (h *host) isOld() bool {
	lastTime := atomic.LoadInt64(&h.lastTime)
	return lastTime < time.Now().Unix()-time.Now().Add(-oldHostDuration).Unix()
}

// isExplicitlyAdded ...
func (h *host) isExplicitlyAdded() bool {
	return h.eaFlag
}

// stop ...
func (h *host) stop() {
	close(h.stopCh)
}

// updLastTime ...
func (h *host) updLastTime() {
	atomic.StoreInt64(&h.lastTime, time.Now().Unix())
}
