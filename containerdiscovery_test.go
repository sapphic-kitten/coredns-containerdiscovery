package containerdiscovery

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/test"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/miekg/dns"
)

func TestContainerDiscovery_ServeDNS(t *testing.T) {
	type testRecord struct {
		name  string
		Type  uint16
		value any
	}
	tests := []struct {
		qname     string
		qtype     uint16
		record    testRecord
		wantCode  int
		wantReply string
		wantErr   bool
	}{
		{
			"example.org",
			dns.TypeA,
			testRecord{"example.org", dns.TypeA, net.ParseIP("127.0.0.1")},
			dns.RcodeSuccess,
			"127.0.0.1",
			false,
		},
		{
			"example.org",
			dns.TypeAAAA,
			testRecord{"example.org", dns.TypeAAAA, net.ParseIP("::1")},
			dns.RcodeSuccess,
			"::1",
			false,
		},
		{
			"1.0.0.127.in-addr.arpa",
			dns.TypePTR,
			testRecord{"example.org", dns.TypeA, net.ParseIP("127.0.0.1")},
			dns.RcodeSuccess,
			"example.org.",
			false,
		},
		{
			"example.net",
			dns.TypeCNAME,
			testRecord{"example.net", dns.TypeCNAME, "example.org."},
			dns.RcodeSuccess,
			"example.org.",
			false,
		},
		{
			"example.net",
			dns.TypeTXT,
			testRecord{"example.net", dns.TypeTXT, []string{"TXT Record 1", "TXT Record 2"}},
			dns.RcodeSuccess,
			"TXT Record 1 TXT Record 2",
			false,
		},
		{
			"example.net",
			dns.TypeANY,
			testRecord{"example.net", dns.TypeTXT, []string{""}},
			dns.RcodeNotImplemented,
			"",
			false,
		},
		{
			"example.net",
			dns.TypeA,
			testRecord{"example.org", dns.TypeTXT, []string{""}},
			dns.RcodeServerFailure,
			"",
			true,
		},
	}

	ctx := context.TODO()
	for _, tt := range tests {
		name := fmt.Sprintf("%s (%s)", tt.qname, dns.TypeToString[tt.qtype])

		t.Run(name, func(t *testing.T) {
			records := map[string][]record{dns.Fqdn(tt.record.name): {{tt.record.Type, tt.record.value}}}
			rm := &recordMap{records: records}
			cd := &ContainerDiscovery{
				records: rm,
				ctx:     ctx,
				Next:    nil,
			}

			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(tt.qname), tt.qtype)
			rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: "127.0.0.1"})
			code, err := cd.ServeDNS(ctx, rec, req)

			if err != nil && !tt.wantErr {
				t.Fatalf("ContainerDiscovery.ServeDNS() error = %v, wantErr %v", err, tt.wantErr)
			}

			if code != tt.wantCode {
				t.Fatalf("ContainerDiscovery.ServeDNS() code = %v, wantCode %v", code, tt.wantCode)
			}

			if len(tt.wantReply) > 0 {
				if len(rec.Msg.Answer) == 0 {
					t.Fatalf("ContainerDiscovery.ServeDNS() expected reply, got none")
				} else {
					got := rec.Msg.Answer[0]
					wantName := dns.Fqdn(tt.qname)
					if got.Header().Name != wantName {
						t.Errorf("ContainerDiscovery.ServeDNS() name = %v, want %v", got.Header().Name, wantName)
					}

					if got.Header().Rrtype != tt.qtype {
						t.Fatalf("ContainerDiscovery.ServeDNS() type = %v, want %v", dns.TypeToString[got.Header().Rrtype], dns.TypeToString[tt.qtype])
					}

					var gotReply string
					switch tt.qtype {
					case dns.TypePTR:
						gotReply = got.(*dns.PTR).Ptr
					case dns.TypeA:
						gotReply = got.(*dns.A).A.String()

					case dns.TypeAAAA:
						gotReply = got.(*dns.AAAA).AAAA.String()

					case dns.TypeCNAME:
						gotReply = got.(*dns.CNAME).Target

					case dns.TypeTXT:
						gotReply = strings.Join(got.(*dns.TXT).Txt, " ")
					}

					if gotReply != tt.wantReply {
						t.Errorf("ContainerDiscovery.ServeDNS() value = %q, want %q", gotReply, tt.wantReply)
					}
				}
			}
		})
	}
}

func TestContainerDiscovery(t *testing.T) {
	type args struct {
		baseDomain       string
		useContainerName bool
		useHostName      bool
		name             string
		labels           map[string]string
		network          map[string]string
	}
	tests := []struct {
		testName string
		args     args
		want     []record
		wantErr  bool
	}{
		{
			testName: "BaseTest",
			args: args{
				baseDomain:       "",
				useContainerName: true,
				useHostName:      false,
				name:             "test1",
				labels: map[string]string{
					"coredns.A":     "127.0.0.1",
					"coredns.CNAME": "localhost",
				},
				network: nil,
			},
			want: []record{
				{dns.TypeA, net.ParseIP("127.0.0.1")},
				{dns.TypeCNAME, dns.Fqdn("localhost")},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			cd := &ContainerDiscovery{
				baseDomain:       tt.args.baseDomain,
				useContainerName: tt.args.useContainerName,
				useHostName:      tt.args.useHostName,
				labelPrefix:      "coredns",
				records:          &recordMap{records: make(map[string][]record)},
				Next:             nil,
			}

			inspect := types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					Name: tt.args.name,
				},
				Config: &container.Config{
					Labels: tt.args.labels,
				},
				NetworkSettings: &types.NetworkSettings{},
			}
			for name, ip := range tt.args.network {
				inspect.NetworkSettings.Networks[name] = &network.EndpointSettings{
					IPAddress: ip,
				}
			}

			if err := cd.addRecords(inspect); (err != nil) != tt.wantErr {
				t.Errorf("ContainerDiscovery.addRecords() error = %v, wantErr %v", err, tt.wantErr)
			}

			var domain string
			if tt.args.useContainerName || tt.args.useHostName {
				domain = tt.args.name
			}
			domain = dnsutil.Join(domain, tt.args.baseDomain)

			if overwrite, ok := tt.args.labels["coredns.domain"]; ok {
				domain = overwrite
			}

			gotMap := make(map[uint16]record)
			for _, got := range cd.records.get(domain) {
				gotMap[got.Type] = got
			}

			for _, want := range tt.want {
				got, ok := gotMap[want.Type]
				if !ok {
					t.Errorf("ContainerDiscovery record of type %q not in recordMap", dns.TypeToString[want.Type])
					continue
				}
				if !reflect.DeepEqual(got.Value, want.Value) {
					t.Errorf("ContainerDiscovery got = %q:%q, want %q:%q", dns.TypeToString[got.Type], got.Value, dns.TypeToString[want.Type], want.Value)
				}
				delete(gotMap, want.Type)
			}

			if len(gotMap) != 0 {
				for _, got := range gotMap {
					t.Errorf("ContainerDiscovery got unwanted record %q:%q", dns.TypeToString[got.Type], got.Value)
				}
			}

			if err := cd.removeRecords(inspect); (err != nil) != tt.wantErr {
				t.Errorf("ContainerDiscovery.removeRecords() error = %v, wantErr %v", err, tt.wantErr)
			}

			for _, got := range cd.records.get(domain) {
				t.Errorf("ContainerDiscovery got unwanted record after removeRecords() %q:%q", dns.TypeToString[got.Type], got.Value)
			}
		})
	}
}
