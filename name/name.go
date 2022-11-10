package name

import (
	"fmt"
	"strings"

	"github.com/namedotcom/go/namecom"

	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

type NameDotComClient struct {
	dnsClient *namecom.NameCom
}

func NewClient(userName string, token string) (*NameDotComClient, error) {
	dnsClient := namecom.New(userName, token)

	return &NameDotComClient{dnsClient}, nil
}

func (c *NameDotComClient) Present(ResolvedZone string, ResolvedFQDN string, Key string) error {
	_, zoneName, err := c.getHostedZone(ResolvedZone)
	if err != nil {
		return fmt.Errorf("alicloud: error getting hosted zones: %v", err)
	}

	recordAttributes := c.newTxtRecord(zoneName, ResolvedFQDN, Key)

	_, err = c.dnsClient.CreateRecord(recordAttributes)

	if err != nil {
		return fmt.Errorf("namecom: error adding domain record: %v", err)
	}

	return nil
}

func (c *NameDotComClient) CleanUp(resolvedZone string, resolvedFQDN string, delKey string) error {
	records, err := c.findTxtRecords(resolvedZone, resolvedFQDN)
	if err != nil {
		return fmt.Errorf("cnamecom: error finding txt records: %v", err)
	}

	_, zone, err := c.getHostedZone(resolvedZone)
	if err != nil {
		return fmt.Errorf("namecom: %v", err)
	}
	for _, rec := range records {
		if delKey == rec.Answer {
			_, err := c.dnsClient.DeleteRecord(&namecom.DeleteRecordRequest{
				DomainName: zone,
				ID:         rec.ID,
			})

			if err != nil {
				return fmt.Errorf("namecom: error deleting domain record: %v", err)
			}
		}
	}
	return nil
}

func (c *NameDotComClient) getHostedZone(resolvedZone string) (string, string, error) {
	domain, err := c.dnsClient.GetDomain(&namecom.GetDomainRequest{
		DomainName: resolvedZone,
	})

	if err != nil {
		return "", "", fmt.Errorf("namecom: error describing domains: %v", err)
	}

	return "", domain.DomainName, nil
}

func (c *NameDotComClient) newTxtRecord(zone, fqdn, value string) *namecom.Record {
	return &namecom.Record{
		DomainName: zone,
		Host:       c.extractRecordName(fqdn, zone),
		Type:       "TXT",
		Answer:     value,
		TTL:        300,
	}
}

func (c *NameDotComClient) findTxtRecords(domain string, fqdn string) ([]namecom.Record, error) {
	_, zoneName, err := c.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	request := &namecom.ListRecordsRequest{
		DomainName: zoneName,
		PerPage:    50,
	}
	recordName := c.extractRecordName(fqdn, zoneName)

	var records []*namecom.Record
	startPage := 1

	for {
		request.Page = int32(startPage)

		response, err := c.dnsClient.ListRecords(request)
		if err != nil {
			return nil, fmt.Errorf("namecom: error describing record: %v", err)
		}

		records = append(records, response.Records...)

		if response.NextPage >= response.LastPage {
			break
		}

		startPage = int(response.NextPage)
	}

	var response []namecom.Record

	for _, record := range records {
		if record.Host == recordName {
			response = append(response, *record)
		}
	}
	return response, nil
}

func (c *NameDotComClient) extractRecordName(fqdn, domain string) string {
	name := util.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}
