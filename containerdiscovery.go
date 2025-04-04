package containerdiscovery

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/docker/docker/api/types/events"
	"github.com/miekg/dns"

	"github.com/containers/podman/v5/libpod/define"
	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/system"
	"github.com/containers/podman/v5/pkg/domain/entities/types"
)

const (
	pluginName = "containers"

	labelEnable = "enable"
	labelDomain = "domain"
	labelA      = "A"
	labelAAAA   = "AAAA"
	labelCNAME  = "CNAME"
	labelTXT    = "TXT"
)

var log = clog.NewWithPlugin(pluginName)

type recordMap struct {
	mutex   sync.RWMutex
	records map[string][]record
}

func (rm *recordMap) get(domain string) []record {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return rm.records[domain]
}

func (rm *recordMap) reverseGet(addr string) []string {
	if addr == "" {
		return nil
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	var domains []string
	for domain, records := range rm.records {
		for _, record := range records {
			if (record.Type == dns.TypeA || record.Type == dns.TypeAAAA) && ip.Equal(record.Value.(net.IP)) {
				domains = append(domains, domain)
			}
		}
	}
	return domains
}

func (rm *recordMap) set(domain string, records []record) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	rm.records[domain] = records
}

func (rm *recordMap) delete(domain string) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.records, domain)
}

type record struct {
	Type  uint16
	Value interface{}
}

type ContainerDiscovery struct {
	socketURL        string
	exposedByDefault bool
	label            string
	network          string
	baseDomain       string
	useContainerName bool
	useHostName      bool

	records    *recordMap
	cancelChan chan bool
	ctx        context.Context

	Next plugin.Handler
}

func newContainerLabel(socketPath string, exposeByDefault bool, label string, network string, baseDomain string, useContainerName bool, useHostName bool) (*ContainerDiscovery, error) {
	if !strings.HasPrefix(socketPath, "/") {
		return nil, ErrSocketPathNotAbsolute
	}

	socketURL, err := url.Parse("uinix://" + socketPath)
	if err != nil {
		return nil, err
	}

	if err := validateLabel(label); err != nil {
		return nil, err
	}

	if _, ok := dns.IsDomainName(baseDomain); !ok {
		return nil, NewInvalidDomainError(baseDomain)
	}

	return &ContainerDiscovery{
		socketURL:        socketURL.String(),
		exposedByDefault: exposeByDefault,
		label:            label,
		network:          network,
		baseDomain:       baseDomain,
		useContainerName: useContainerName,
		useHostName:      useHostName,
		records:          new(recordMap),
		cancelChan:       make(chan bool),
	}, nil
}

func (cd *ContainerDiscovery) run() {
	ctx, cancel := context.WithCancel(context.Background())
	ctx, err := bindings.NewConnection(ctx, cd.socketURL)
	if err != nil {
		log.Fatalf("failed to connect to socket %q: %v", cd.socketURL, err)
	}

	exposeLabelFilter := []string{buildLabelWithValue(cd.label, labelEnable, "true")}

	listFilter := map[string][]string{
		"status": {"running"},
	}
	if !cd.exposedByDefault {
		listFilter["label"] = exposeLabelFilter
	}

	containerList, err := containers.List(ctx, new(containers.ListOptions).WithFilters(listFilter))
	if err != nil {
		log.Fatalf("failed to list containers: %v", err)
	}

	for _, container := range containerList {
		inspect, err := containers.Inspect(ctx, container.ID, nil)
		if err != nil {
			log.Fatalf("failed to inspect container %q: %v", container.ID, err)
		}

		if err := cd.addRecords(inspect); err != nil {
			log.Errorf("failed to generate dns records for %q, %v", container.ID, err)
		}
	}

	eventFilter := map[string][]string{
		"container": {"start", "die"},
	}
	if !cd.exposedByDefault {
		eventFilter["label"] = exposeLabelFilter
	}

	eventChan := make(chan types.Event)
	if err := system.Events(ctx, eventChan, cd.cancelChan, new(system.EventsOptions).WithFilters(eventFilter)); err != nil {
		log.Fatalf("failed to setup container event listener: %v", err)
	}

	for {
		select {
		case event, ok := <-eventChan:
			if !ok {
				log.Error("event channel closed unexpectedly")
				defer cancel()
			}

			inspect, err := containers.Inspect(ctx, event.Actor.ID, nil)
			if err != nil {
				log.Errorf("inspect failed on container %q: %v", event.Actor.ID, err)
				continue
			}

			switch event.Action {
			case events.ActionStart:
				if err := cd.addRecords(inspect); err != nil {
					log.Errorf("failed to add records for %q: %v", event.Actor.ID, err)
				}

			case events.ActionDie:
				if err := cd.removeRecords(inspect); err != nil {
					log.Errorf("failed to remove records for %q: %v", event.Actor.ID, err)
				}
			}

		case <-ctx.Done():
			log.Info("connection closed, shutting down")
		}
	}
}

func (cd *ContainerDiscovery) addRecords(inspect *define.InspectContainerData) error {
	var domain string
	var records []record
	var hasCNAME bool = false

	if cd.useHostName {
		domain = inspect.Config.Hostname
	}

	if cd.useContainerName {
		domain = strings.ToLower(strings.ReplaceAll(inspect.Name, "/", ""))
	}

	if cd.baseDomain != "" {
		domain = dnsutil.Join(domain, cd.baseDomain)
	}

	if cd.network != "" {
		network, ok := inspect.NetworkSettings.Networks[cd.network]
		if !ok {
			return NewUnknownNetworkError(cd.network)
		}

		ip := net.ParseIP(network.IPAddress)
		if ip == nil {
			return NewInvalidIPAddressError(network.IPAddress)
		}

		if ip.To4() != nil {
			records = append(records, record{dns.TypeA, ip})
		} else {
			records = append(records, record{dns.TypeAAAA, ip})
		}
	}

	for label, value := range inspect.Config.Labels {
		switch label {
		case buildLabel(cd.label, labelDomain):
			domain = strings.ToLower(value)

		case buildLabel(cd.label, labelA):
			ip := net.ParseIP(value)
			if ip == nil || ip.To4() == nil {
				return NewInvalidARecordError(value)
			}
			records = append(records, record{dns.TypeA, ip})

		case buildLabel(cd.label, labelAAAA):
			ip := net.ParseIP(value)
			if ip == nil || ip.To16() == nil {
				return NewInvalidAAAARecordError(value)
			}
			records = append(records, record{dns.TypeAAAA, ip})

		case buildLabel(cd.label, labelCNAME):
			if _, ok := dns.IsDomainName(value); !ok {
				return NewInvalidCNAMERecordError(value)
			}
			if !hasCNAME {
				hasCNAME = true
				records = append(records, record{dns.TypeCNAME, dns.Fqdn(value)})
			} else {
				log.Warning("domains can only have one CNAME record")
			}

		case buildLabel(cd.label, labelTXT):
			records = append(records, record{dns.TypeTXT, strings.Fields(value)})
		}
	}

	if _, ok := dns.IsDomainName(domain); !ok {
		return NewInvalidDomainError(domain)
	}

	cd.records.set(dns.Fqdn(domain), records)
	return nil
}

func (cd *ContainerDiscovery) removeRecords(inspect *define.InspectContainerData) error {
	var domain string
	if cd.useHostName {
		domain = inspect.Config.Hostname
	}

	if cd.useContainerName {
		domain = strings.ToLower(strings.ReplaceAll(inspect.Name, "/", ""))
	}

	if domain != "" {
		domain = fmt.Sprintf("%s.%s", domain, cd.baseDomain)
	}

	value, ok := inspect.Config.Labels[buildLabel(cd.label, labelDomain)]
	if ok {
		domain = value
	}

	if domain == "" {
		return ErrNoFQDN
	}

	cd.records.delete(domain)
	return nil
}

func (cd *ContainerDiscovery) OnStartup() error {
	log.Infof("starting...")
	go cd.run()
	return nil
}

func (cd *ContainerDiscovery) OnShutdown() error {
	cd.cancelChan <- true
	return nil
}

func (cd *ContainerDiscovery) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()

	if cd.ctx.Err() != nil {
		log.Error("connection to engine lost, falling through")
		return plugin.NextOrFailure(cd.Name(), cd.Next, ctx, w, r)
	}

	answers := []dns.RR{}
	records := cd.records.get(qname)

	switch state.QType() {
	case dns.TypePTR:
		names := cd.records.reverseGet(dnsutil.ExtractAddressFromReverse(qname))
		if len(names) == 0 {
			return plugin.NextOrFailure(cd.Name(), cd.Next, ctx, w, r)
		}
		answers = ptr(qname, names)

	case dns.TypeA:
		answers = a(qname, filterByType(records, dns.TypeA))

	case dns.TypeAAAA:
		answers = aaaa(qname, filterByType(records, dns.TypeAAAA))

	case dns.TypeCNAME:
		answers = cname(qname, filterByType(records, dns.TypeCNAME))

	case dns.TypeTXT:
		answers = txt(qname, filterByType(records, dns.TypeTXT))
	}

	if len(answers) == 0 && len(records) == 0 {
		return plugin.NextOrFailure(cd.Name(), cd.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Compress = true
	m.Answer = answers

	if err := w.WriteMsg(m); err != nil {
		log.Errorf("error while writing answer: %v", err)
		return dns.RcodeServerFailure, err
	}

	return dns.RcodeSuccess, nil
}

func filterByType(records []record, Type uint16) []record {
	if Type == dns.TypeANY {
		return records
	}

	var ret []record
	for _, record := range records {
		if record.Type == Type {
			ret = append(ret, record)
		}
	}
	return ret
}

func ptr(zone string, names []string) []dns.RR {
	answers := make([]dns.RR, len(names))
	for i, name := range names {
		answers[i] = &dns.PTR{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 1800},
			Ptr: dns.Fqdn(name),
		}
	}
	return answers
}

func a(name string, records []record) []dns.RR {
	answers := make([]dns.RR, len(records))
	for i, record := range records {
		answers[i] = &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1800},
			A:   record.Value.(net.IP),
		}
	}
	return answers
}

func aaaa(name string, records []record) []dns.RR {
	answers := make([]dns.RR, len(records))
	for i, record := range records {
		answers[i] = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1800},
			AAAA: record.Value.(net.IP),
		}
	}
	return answers
}

func cname(name string, records []record) []dns.RR {
	answers := make([]dns.RR, len(records))
	for i, record := range records {
		answers[i] = &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1800},
			Target: record.Value.(string),
		}
	}
	return answers
}

func txt(name string, records []record) []dns.RR {
	answers := make([]dns.RR, len(records))
	for i, record := range records {
		answers[i] = &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1800},
			Txt: record.Value.([]string),
		}
	}
	return answers
}

func (cd *ContainerDiscovery) Name() string { return pluginName }
