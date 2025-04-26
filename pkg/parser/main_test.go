package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/types"
)

func TestProcessSimpleScan(t *testing.T) {
	// Create temporary test file
	testFile, err := os.CreateTemp("", "ips_list_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(testFile.Name())

	// Write test data
	testIPs := []string{
		"1.2.3.4",
		"8.8.8.8",
		"9.9.9.9",
		"203.0.113.1",
		"192.0.2.1",
	}

	testContent := ""
	for _, ip := range testIPs {
		testContent += ip + "\n"
	}

	if _, err := testFile.Write([]byte(testContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	testFile.Close()

	// Reopen the file for reading
	file, err := os.Open(testFile.Name())
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	// Create parser
	var parser Parser
	parser = *parser.NewSimpleParser(file)

	// Process the scan
	parser.ProcessSimpleScan()

	// Check results
	if len(parser.ScanRecords) != len(testIPs) {
		t.Errorf("Expected %d records, got %d", len(testIPs), len(parser.ScanRecords))
	}

	// Check that each IP address is in the records
	for _, ip := range testIPs {
		found := false
		for _, record := range parser.ScanRecords {
			if record.Ip == ip {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IP %s not found in records", ip)
		}
	}
}

func TestProcessNucleiScan(t *testing.T) {
	// Create a simple test nuclei output
	sampleOutput := []byte(`{
		"template-id": "generic-detection",
		"info": {
			"name": "Generic Detection",
			"author": ["Test Author"],
			"tags": ["tag1", "tag2"],
			"description": "Test vulnerability detection",
			"reference": ["https://example.com/reference"],
			"severity": "info"
		},
		"matcher-name": "generic",
		"type": "http",
		"host": "example.com",
		"url": "http://example.com/",
		"matched-at": "http://example.com/",
		"ip": "192.0.2.1",
		"timestamp": "2022-06-06T08:37:15.398363+02:00",
		"matcher-status": true
	}`)

	// Create temporary test file
	testFile, err := os.CreateTemp("", "nuclei_output_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(testFile.Name())

	if _, err := testFile.Write(sampleOutput); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	testFile.Close()

	// Reopen the file for reading
	file, err := os.Open(testFile.Name())
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	// Create parser
	var parser Parser
	parser = *parser.NewParser(file)

	// Process the scan
	parser.ProcessNucleiScan()

	// Check results
	if len(parser.ScanRecords) != 1 {
		t.Errorf("Expected 1 record, got %d", len(parser.ScanRecords))
	}

	// Check record details
	if len(parser.ScanRecords) > 0 {
		record := parser.ScanRecords[0]
		if record.Ip != "192.0.2.1" {
			t.Errorf("Expected IP 192.0.2.1, got %s", record.Ip)
		}

		if record.Info.Name != "Generic Detection" {
			t.Errorf("Expected name 'Generic Detection', got %s", record.Info.Name)
		}
	}
}

// Helper function to create a test directory structure and files
func setupTestFiles(t *testing.T) (string, func()) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "parser-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create IP list file
	ipListFile := filepath.Join(tempDir, "ips_list.txt")
	err = os.WriteFile(ipListFile, []byte("8.8.8.8\n192.0.2.1\n"), 0644)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create IP list file: %v", err)
	}

	// Create nuclei output file
	nucleiFile := filepath.Join(tempDir, "nuclei_output.json")
	nucleiData := []byte(`{
		"template-id": "test-template",
		"info": {"name": "Test Template", "severity": "info"},
		"ip": "192.0.2.1",
		"matcher-status": true
	}`)
	err = os.WriteFile(nucleiFile, nucleiData, 0644)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create nuclei output file: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return tempDir, cleanup
}

func TestWriteOutput(t *testing.T) {
	// Setup test files
	testDir, cleanup := setupTestFiles(t)
	defer cleanup()

	outputPath := filepath.Join(testDir, "output.json")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Create a parser with some merge results
	parser := Parser{}

	// Mock some merge results
	mergeResult := types.MergeResult{
		EnrichInfo: types.EnrichInfo{
			Ip:          "192.0.2.1",
			AbuseSource: "test",
			Abuse:       "test@example.com",
			Prefix:      "192.0.2.0/24",
			Asn:         "12345",
			Holder:      "Test Organization",
			Country:     "US",
			City:        "Test City",
		},
		NucleiJsonRecord: types.NucleiJsonRecord{
			TemplateId: "test-template",
			Info: struct {
				Name           string   `json:"name"`
				Author         []string `json:"author"`
				Tags           []string `json:"tags"`
				Reference      []string `json:"reference"`
				Severity       string   `json:"severity"`
				Classification struct {
					CveId       []string `json:"cve-id"`
					CweId       []string `json:"cwe-id"`
					CvssMetrics string   `json:"cvss-metrics"`
					CvssScore   float32  `json:"cvss-score"`
				} `json:"classification"`
				Description string `json:"description"`
			}{
				Name:     "Test Record",
				Severity: "info",
			},
			Ip:            "192.0.2.1",
			Timestamp:     "2022-06-06T08:37:15.398363+02:00",
			MatcherStatus: true,
		},
	}

	parser.MergeResults = append(parser.MergeResults, mergeResult)

	// Write output
	err = parser.WriteOutput(outputFile)
	if err != nil {
		t.Fatalf("WriteOutput failed: %v", err)
	}

	// Verify file exists
	outputFile.Close() // Close for reading
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatalf("Output file was not created")
	}

	// Read and verify content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse output JSON: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 record in output, got %d", len(result))
	}
}
