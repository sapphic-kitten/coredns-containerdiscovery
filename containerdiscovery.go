package containerdiscovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/fall"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/miekg/dns"
)

const pluginName = "containers"

var log = clog.NewWithPlugin(pluginName)

type record struct {
	Type  uint16
	Value any
}

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

type ContainerDiscovery struct {
	socketURL        string
	exposedByDefault bool
	labelPrefix      string
	baseDomain       string
	useContainerName bool
	useHostName      bool

	records *recordMap
	ctx     context.Context
	cancel  context.CancelFunc

	Next plugin.Handler
	Fall fall.F
}

func newContainerDiscovery(cfg *config) *ContainerDiscovery {
	ctx, cancel := context.WithCancel(context.Background())

	return &ContainerDiscovery{
		socketURL:        cfg.endpoint,
		exposedByDefault: cfg.exposeByDefault,
		labelPrefix:      cfg.labelPrefix,
		baseDomain:       cfg.baseDomain,
		useContainerName: cfg.useContainerName,
		useHostName:      cfg.useHostName,

		records: &recordMap{records: make(map[string][]record)},
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (cd *ContainerDiscovery) run() {
	client, err := client.NewClientWithOpts(client.WithHost(cd.socketURL), client.WithAPIVersionNegotiation())

	if err != nil {
		log.Fatalf("failed to connect to socket %q: %v", cd.socketURL, err)
	}
	defer client.Close()

	enableFilter := fmt.Sprintf("%s.enable=true", cd.labelPrefix)
	listOptions := container.ListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{Key: "status", Value: "running"}),
	}
	if !cd.exposedByDefault {
		listOptions.Filters.Add("label", enableFilter)
	}

	log.Debug("listing containers...")
	containerList, err := client.ContainerList(cd.ctx, listOptions)
	if err != nil {
		log.Fatalf("failed to list containers: %v", err)
	}

	for _, container := range containerList {
		inspect, err := client.ContainerInspect(cd.ctx, container.ID)
		if err != nil {
			log.Fatalf("failed to inspect container %q: %v", container.ID, err)
		}

		if err := cd.addRecords(inspect); err != nil {
			log.Errorf("failed to generate dns records for %q, %v", container.ID, err)
		}
	}

	eventOptions := events.ListOptions{
		Filters: filters.NewArgs(
			filters.KeyValuePair{Key: "event", Value: "start"},
			filters.KeyValuePair{Key: "event", Value: "die"},
		),
	}
	if !cd.exposedByDefault {
		eventOptions.Filters.Add("label", enableFilter)
	}

	eventChan, errChan := client.Events(cd.ctx, eventOptions)

	for {
		select {
		case event := <-eventChan:
			log.Debugf("container event fired: %q, %q", event.Action, event.Actor.ID)
			inspect, err := client.ContainerInspect(cd.ctx, event.Actor.ID)
			if err != nil {
				log.Errorf("inspect failed on container %q: %v", event.Actor.ID, err)
				continue
			}

			switch event.Action {
			case events.ActionStart:
				log.Debugf("adding records for %q", inspect.Name)
				if err := cd.addRecords(inspect); err != nil {
					log.Errorf("failed to add records for %q: %v", inspect.Name, err)
				}

			case events.ActionDie:
				log.Debugf("removing records for %q", inspect.Name)
				if err := cd.removeRecords(inspect); err != nil {
					log.Errorf("failed to remove records for %q: %v", inspect.Name, err)
				}
			}

		case err := <-errChan:
			if errors.Is(err, io.EOF) {
				log.Info("connection to container engine closed")
				cd.cancel()
			} else if err != nil {
				log.Errorf("error while listening to container engine events: %v", err)
			}

		case <-cd.ctx.Done():
			log.Info("shutting down")
			return
		}
	}
}

func (cd *ContainerDiscovery) addRecords(inspect container.InspectResponse) error {
	clog.Debugf("adding records for container %q", inspect.Name)

	groups, err := parseLabels(inspect.Config.Labels, cd.labelPrefix)
	if err != nil {
		return err
	}

	for group, labels := range groups {
		var domain string
		var networkName string
		var records []record

		hasCNAME := false
		for _, label := range labels {
			switch label.Type {
			case Domain:
				domain = label.Value

			case Network:
				networkName = label.Value

			case A:
				ip := net.ParseIP(label.Value)
				if ip == nil || ip.To4() == nil {
					return NewInvalidARecordError(label.Value)
				}
				records = append(records, record{dns.TypeA, ip})

			case AAAA:
				ip := net.ParseIP(label.Value)
				if ip == nil || ip.To16() == nil {
					return NewInvalidAAAARecordError(label.Value)
				}
				records = append(records, record{dns.TypeAAAA, ip})

			case CNAME:
				if _, ok := dns.IsDomainName(label.Value); !ok {
					return NewInvalidCNAMERecordError(label.Value)
				}
				if !hasCNAME {
					hasCNAME = true
					records = append(records, record{dns.TypeCNAME, dns.Fqdn(label.Value)})
				} else {
					log.Warningf("multiple CNAME records defined in group %q of %q", group, inspect.Name)
				}

			case TXT:
				records = append(records, record{dns.TypeTXT, strings.Fields(label.Value)})
			}
		}

		if networkName != "" {
			var IPAddress string
			if networkName == "default" {
				IPAddress = inspect.NetworkSettings.IPAddress
			} else {
				log.Debugf("using network %q", networkName)
				network, ok := inspect.NetworkSettings.Networks[networkName]
				if !ok {
					return NewUnknownNetworkError(networkName)
				}
				IPAddress = network.IPAddress
			}
			ip := net.ParseIP(IPAddress)
			if ip == nil {
				return NewInvalidIPAddressError(IPAddress)
			}

			if ip.To4() != nil {
				records = append(records, record{dns.TypeA, ip})
			} else {
				records = append(records, record{dns.TypeAAAA, ip})
			}
		}

		if domain == "" {
			if cd.useContainerName {
				domain = strings.ToLower(strings.ReplaceAll(inspect.Name, "/", ""))
			} else if cd.useHostName {
				domain = inspect.Config.Hostname
			} else {
				log.Warningf("no domain name found for group %q of %q", group, inspect.Name)
				continue
			}

			domain = dnsutil.Join(domain, cd.baseDomain)
		}

		if _, ok := dns.IsDomainName(domain); !ok {
			log.Errorf("invalid domain for group %q of %q", group, inspect.Name)
			return NewInvalidDomainError(domain)
		}

		if cd.records.get(domain) != nil {
			log.Warningf("duplicate domain definition in group %q of %q", group, inspect.Name)
			continue
		}

		if len(records) == 0 {
			log.Infof("no records for group %q of %q created", group, inspect.Name)
		}

		for _, record := range records {
			clog.Debugf("created record %q, type %q", record.Value, record.Type)
		}

		cd.records.set(dns.Fqdn(domain), records)
	}

	return nil
}

func (cd *ContainerDiscovery) removeRecords(inspect container.InspectResponse) error {
	groups, err := parseLabels(inspect.Config.Labels, cd.labelPrefix)
	if err != nil {
		return err
	}

	for group, labels := range groups {
		var domain string
		for _, label := range labels {
			if label.Type == Domain {
				domain = label.Value
			}
		}

		if domain == "" {
			if cd.useContainerName {
				domain = strings.ToLower(strings.ReplaceAll(inspect.Name, "/", ""))
			} else if cd.useHostName {
				domain = inspect.Config.Hostname
			} else {
				log.Warningf("no domain name found for group %q of %q", group, inspect.Name)
				continue
			}

			domain = dnsutil.Join(domain, cd.baseDomain)
		}

		if _, ok := dns.IsDomainName(domain); !ok {
			log.Errorf("invalid domain for group %q of %q", group, inspect.Name)
			return NewInvalidDomainError(domain)
		}
		cd.records.delete(dns.Fqdn(domain))
	}
	return nil
}

func (cd *ContainerDiscovery) OnStartup() error {
	log.Debugf("starting...")
	go cd.run()
	return nil
}

func (cd *ContainerDiscovery) OnShutdown() error {
	log.Debug("shutting down")
	cd.cancel()
	return nil
}

func (cd *ContainerDiscovery) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.QName()

	if cd.ctx.Err() != nil {
		log.Error("connection to engine lost, falling through")
		return plugin.NextOrFailure(cd.Name(), cd.Next, ctx, w, r)
	}

	records := cd.records.get(qname)
	var answers []dns.RR
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
		log.Debugf("no record for %q found", qname)
		if cd.Fall.Through(qname) {
			return plugin.NextOrFailure(cd.Name(), cd.Next, ctx, w, r)
		}
		return dns.RcodeServerFailure, nil
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
	if len(records) > 1 {
		log.Warningf("found multiple cname records for %q", name)
	}
	answers := []dns.RR{&dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1800},
		Target: records[0].Value.(string),
	}}
	return answers
}

func txt(name string, records []record) []dns.RR {
	answers := make([]dns.RR, len(records))
	for i, record := range records {
		answers[i] = &dns.TXT{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1800},
			Txt: record.Value.([]string),
		}
	}
	return answers
}

func (cd *ContainerDiscovery) Name() string { return pluginName }
