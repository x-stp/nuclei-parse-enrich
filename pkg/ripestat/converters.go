package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Base types for response parsing
type AbuseContactFinderBase struct {
	Data struct {
		AbuseContacts []string `json:"abuse_contacts"`
	} `json:"data"`
}

type NetworkInfoBase struct {
	Data NetworkInfo `json:"data"`
}

type ASOverviewBase struct {
	Data ASOverview `json:"data"`
}

type MaxmindGeoLiteBase struct {
	Data MaxmindGeoLite `json:"data"`
}

func ConvertAbuseContactsData(data []byte) ([]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	// First check if we have a status field
	var baseResponse struct {
		Status string `json:"status"`
		Data   struct {
			AbuseContacts []string `json:"abuse_contacts"`
		} `json:"data"`
	}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(&baseResponse)
	if err != nil {
		return nil, fmt.Errorf("ConvertAbuseContactsData: failed to Unmarshal data: %v", err)
	}

	// Check if the status is OK
	if baseResponse.Status != "ok" {
		return nil, fmt.Errorf("ConvertAbuseContactsData: API returned non-ok status")
	}

	return baseResponse.Data.AbuseContacts, nil
}

func ConvertNetworkInfoData(data []byte) (NetworkInfo, error) {
	if len(data) == 0 {
		return NetworkInfo{}, fmt.Errorf("empty data")
	}

	// First check if we have a status field
	var baseResponse struct {
		Status string `json:"status"`
		Data   struct {
			Prefix string        `json:"prefix"`
			ASNs   []interface{} `json:"asns"` // Can be strings or integers
			Holder string        `json:"holder"`
		} `json:"data"`
	}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(&baseResponse)
	if err != nil {
		return NetworkInfo{}, fmt.Errorf("ConvertNetworkInfoData: failed to unmarshal data: %v", err)
	}

	// Check if the status is OK
	if baseResponse.Status != "ok" {
		return NetworkInfo{}, fmt.Errorf("ConvertNetworkInfoData: API returned non-ok status")
	}

	// Convert ASNs to proper type
	asns := make([]ASN, 0, len(baseResponse.Data.ASNs))
	for _, rawASN := range baseResponse.Data.ASNs {
		// Try as string first
		if asnStr, ok := rawASN.(string); ok {
			asnVal, err := strconv.Atoi(strings.TrimPrefix(asnStr, "AS"))
			if err != nil {
				continue
			}
			asns = append(asns, ASN(asnVal))
		} else if asnNum, ok := rawASN.(float64); ok {
			// JSON numbers come as float64
			asns = append(asns, ASN(int(asnNum)))
		}
	}

	return NetworkInfo{
		Prefix: baseResponse.Data.Prefix,
		ASNs:   asns,
		Holder: baseResponse.Data.Holder,
	}, nil
}

func ConvertASOverviewData(data []byte) (ASOverview, error) {
	if len(data) == 0 {
		return ASOverview{}, fmt.Errorf("empty data")
	}

	// First check if we have a status field
	var baseResponse struct {
		Status string `json:"status"`
		Data   struct {
			Holder   string `json:"holder"`
			Resource string `json:"resource"`
			ASNumber any    `json:"asn"` // Might be missing in some responses
		} `json:"data"`
	}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(&baseResponse)
	if err != nil {
		return ASOverview{}, fmt.Errorf("ConvertASOverviewData: failed to unmarshal data: %v", err)
	}

	// Check if the status is OK
	if baseResponse.Status != "ok" {
		return ASOverview{}, fmt.Errorf("ConvertASOverviewData: API returned non-ok status")
	}

	// If ASNumber is missing, try to parse from Resource
	var asnValue ASN
	if baseResponse.Data.ASNumber != nil {
		// Try as string first
		if asnStr, ok := baseResponse.Data.ASNumber.(string); ok {
			asnVal, err := strconv.Atoi(strings.TrimPrefix(asnStr, "AS"))
			if err == nil {
				asnValue = ASN(asnVal)
			}
		} else if asnNum, ok := baseResponse.Data.ASNumber.(float64); ok {
			// JSON numbers come as float64
			asnValue = ASN(int(asnNum))
		}
	} else if baseResponse.Data.Resource != "" {
		// Try to extract ASN from Resource
		asnVal, err := strconv.Atoi(strings.TrimPrefix(baseResponse.Data.Resource, "AS"))
		if err == nil {
			asnValue = ASN(asnVal)
		}
	}

	return ASOverview{
		Holder:   baseResponse.Data.Holder,
		ASNumber: asnValue,
	}, nil
}

func ConvertGeolocationData(data []byte) (MaxmindGeoLite, error) {
	if len(data) == 0 {
		return MaxmindGeoLite{}, fmt.Errorf("empty data")
	}

	// First check if we have a status field
	var baseResponse struct {
		Status string `json:"status"`
		Data   struct {
			LocatedResources []struct {
				Locations []struct {
					Country string `json:"country"`
					City    string `json:"city"`
				} `json:"locations"`
			} `json:"located_resources"`
		} `json:"data"`
	}

	err := json.NewDecoder(bytes.NewReader(data)).Decode(&baseResponse)
	if err != nil {
		return MaxmindGeoLite{}, fmt.Errorf("ConvertGeolocationData: failed to unmarshal data: %v", err)
	}

	// Check if the status is OK
	if baseResponse.Status != "ok" {
		return MaxmindGeoLite{}, fmt.Errorf("ConvertGeolocationData: API returned non-ok status")
	}

	// Check if we have located resources and locations
	if len(baseResponse.Data.LocatedResources) == 0 ||
		len(baseResponse.Data.LocatedResources[0].Locations) == 0 {
		return MaxmindGeoLite{}, fmt.Errorf("ConvertGeolocationData: no location data found")
	}

	// Get the first location
	location := baseResponse.Data.LocatedResources[0].Locations[0]

	return MaxmindGeoLite{
		City:        location.City,
		CountryCode: location.Country,
	}, nil
}

// UnmarshalJSON implements custom unmarshaling for ASN values from RIPE Stat API
// RIPE API may return ASNs as strings or integers
func (a *ASN) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an integer first
	var intValue int
	if err := json.Unmarshal(data, &intValue); err == nil {
		*a = ASN(intValue)
		return nil
	}

	// If that fails, try to unmarshal as a string
	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err != nil {
		return err
	}

	// Remove any "AS" prefix if present
	stringValue = strings.TrimPrefix(stringValue, "AS")
	stringValue = strings.TrimSpace(stringValue)

	// Convert the string to an integer
	intValue, err := strconv.Atoi(stringValue)
	if err != nil {
		return err
	}

	*a = ASN(intValue)
	return nil
}

// Int returns the int value of the ASN
func (a ASN) Int() int {
	return int(a)
}

// MarshalJSON implements custom marshaling for ASN
func (a ASN) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(a))
}

// RipeTime is a custom time type that handles the RIPE API time format
type RipeTime time.Time

// UnmarshalJSON implements custom unmarshaling for time values from RIPE Stat API
// RIPE API may return times in various formats, with or without timezone information
func (rt *RipeTime) UnmarshalJSON(data []byte) error {
	// Remove the quotes from the JSON string
	s := strings.Trim(string(data), "\"")
	if s == "" || s == "null" {
		*rt = RipeTime(time.Time{})
		return nil
	}

	// Try to parse with timezone first
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		*rt = RipeTime(t)
		return nil
	}

	// Try to parse without timezone - using multiple formats
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.999999",
	}

	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			*rt = RipeTime(t)
			return nil
		}
	}

	// Return original error if none of the formats match
	return err
}

// Time returns the time.Time value
func (rt RipeTime) Time() time.Time {
	return time.Time(rt)
}

// MarshalJSON implements custom marshaling for RipeTime
func (rt RipeTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(rt).Format(time.RFC3339))
}

// IsCached returns whether the response was served from cache
func (r Response) IsCached() bool {
	return r.Cached
}
