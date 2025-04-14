package containerdiscovery

import (
	"fmt"
)

type InvalidDomainError struct {
	domainName string
}

func NewInvalidDomainError(domainName string) error {
	return InvalidDomainError{domainName}
}

func (e InvalidDomainError) Error() string {
	return fmt.Sprintf("invalid domain name: %q", e.domainName)
}

type UnknownNetworkError struct {
	network string
}

func NewUnknownNetworkError(network string) error {
	return UnknownNetworkError{network}
}

func (e UnknownNetworkError) Error() string {
	return fmt.Sprintf("unknown network %q", e.network)
}

type InvalidIPAddressError struct {
	address string
}

func NewInvalidIPAddressError(address string) error {
	return InvalidIPAddressError{address}
}

func (e InvalidIPAddressError) Error() string {
	return fmt.Sprintf("invalid IpAddress %q", e.address)
}

type InvalidARecordError struct {
	record string
}

func NewInvalidARecordError(record string) error {
	return InvalidARecordError{record}
}

func (e InvalidARecordError) Error() string {
	return fmt.Sprintf("invalid A record %q", e.record)
}

type InvalidAAAARecordError struct {
	record string
}

func NewInvalidAAAARecordError(record string) error {
	return InvalidAAAARecordError{record}
}

func (e InvalidAAAARecordError) Error() string {
	return fmt.Sprintf("invalid AAAA record %q", e.record)
}

type InvalidCNAMERecordError struct {
	record string
}

func NewInvalidCNAMERecordError(record string) error {
	return InvalidCNAMERecordError{record}
}

func (e InvalidCNAMERecordError) Error() string {
	return fmt.Sprintf("invalid CNAME record %q", e.record)
}
