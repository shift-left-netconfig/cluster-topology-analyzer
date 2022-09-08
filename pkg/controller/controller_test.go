package controller

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/cluster-topology-analyzer/pkg/common"
)

// TestOutput calls controller.Start() with an example repo dir tests/onlineboutique/ ,
// checking for the json output to match expected output at tests/expected_output.json
func TestConnectionsOutput(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "onlineboutique", "kubernetes-manifests.yaml")
	outFile := filepath.Join(testsDir, "onlineboutique", "output.json")
	expectedOutput := filepath.Join(testsDir, "onlineboutique", "expected_output.json")
	args := getTestArgs(dirPath, outFile, false)

	err := Start(args)
	if err != nil {
		t.Fatalf("expected err to be nil, but got %v", err)
	}

	res, err := compareFiles(expectedOutput, outFile)

	if err != nil {
		t.Fatalf("expected err to be nil, but got %v", err)
	}
	if !res {
		t.Fatalf("expected res to be true, but got false")
	}

	os.Remove(outFile)
}

func TestDirScan(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "onlineboutique")
	outFile := filepath.Join(dirPath, "output.json")
	expectedOutput := filepath.Join(dirPath, "expected_dirscan_output.json")
	args := getTestArgs(dirPath, outFile, false)

	err := Start(args)
	if err != nil {
		t.Fatalf("expected err to be nil, but got %v", err)
	}

	res, err := compareFiles(expectedOutput, outFile)

	if err != nil {
		t.Fatalf("expected err to be nil, but got %v", err)
	}
	if !res {
		t.Fatalf("expected res to be true, but got false")
	}

	os.Remove(outFile)
}

type TestDetails struct {
	dirPath        string
	outFile        string
	expectedOutput string
}

func TestNetpolsJsonOutput(t *testing.T) {
	testsDir := getTestsDir()
	tests := map[string]TestDetails{} // map from test name to test details
	tests["onlineboutique"] = TestDetails{dirPath: filepath.Join(testsDir, "onlineboutique", "kubernetes-manifests.yaml"),
		outFile:        filepath.Join(testsDir, "onlineboutique", "output.json"),
		expectedOutput: filepath.Join(testsDir, "onlineboutique", "expected_netpol_output.json")}
	tests["sockshop"] = TestDetails{dirPath: filepath.Join(testsDir, "sockshop", "manifests"),
		outFile:        filepath.Join(testsDir, "sockshop", "output.json"),
		expectedOutput: filepath.Join(testsDir, "sockshop", "expected_netpol_output.json")}
	tests["wordpress"] = TestDetails{dirPath: filepath.Join(testsDir, "k8s_wordpress_example"),
		outFile:        filepath.Join(testsDir, "k8s_wordpress_example", "output.json"),
		expectedOutput: filepath.Join(testsDir, "k8s_wordpress_example", "expected_netpol_output.json")}
	tests["guestbook"] = TestDetails{dirPath: filepath.Join(testsDir, "k8s_guestbook"),
		outFile:        filepath.Join(testsDir, "k8s_guestbook", "output.json"),
		expectedOutput: filepath.Join(testsDir, "k8s_guestbook", "expected_netpol_output.json")}

	for testName, testDetails := range tests {
		args := getTestArgs(testDetails.dirPath, testDetails.outFile, true)
		err := Start(args)
		if err != nil {
			t.Fatalf("Test %v: expected Start to return no error, but got %v", testName, err)
		}
		res, err := compareFiles(testDetails.expectedOutput, testDetails.outFile)
		if err != nil {
			t.Fatalf("Test %v: expected err to be nil, but got %v", testName, err)
		}
		if !res {
			t.Fatalf("Test %v: expected res to be true, but got false", testName)
		}
		os.Remove(testDetails.outFile)
	}
}

func TestPoliciesSynthesizerAPI(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "onlineboutique", "kubernetes-manifests.yaml")
	outFile := filepath.Join(testsDir, "onlineboutique", "output.json")
	expectedOutput := filepath.Join(testsDir, "onlineboutique", "expected_netpol_interface_output.json")

	logger := NewDefaultLogger()
	synthesizer := NewPoliciesSynthesizer(WithLogger(logger))
	netpols, err := synthesizer.PoliciesFromFolderPath(dirPath)
	if err != nil {
		t.Fatalf("expected no fatal errors, but got %v", err)
	}
	fileScanningErrors := synthesizer.Errors()
	if len(fileScanningErrors) > 0 {
		t.Fatalf("expected no file-scanning errors, but got %v", fileScanningErrors)
	}
	if len(netpols) == 0 {
		t.Fatalf("expected policies to be non-empty, but got empty")
	}

	buf, _ := json.MarshalIndent(netpols, "", "    ")
	fp, err := os.Create(outFile)
	if err != nil {
		t.Fatalf("failed opening output file: %v", err)
	}
	_, err = fp.Write(buf)
	if err != nil {
		t.Fatalf("failed writing to output file: %v", err)
	}
	fp.Close()
	res, err := compareFiles(expectedOutput, outFile)
	if err != nil {
		t.Fatalf("expected err to be nil, but got %v", err)
	}
	if !res {
		t.Fatalf("expected res to be true, but got false")
	}

	os.Remove(outFile)
}

func TestPoliciesSynthesizerAPIFatalError(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "badPath")

	logger := NewDefaultLogger()
	synthesizer := NewPoliciesSynthesizer(WithLogger(logger))
	netpols, err := synthesizer.PoliciesFromFolderPath(dirPath)
	if err == nil {
		t.Fatal("expected a fatal error, but got none")
	}
	fileScanningErrors := synthesizer.Errors()
	if len(fileScanningErrors) != 1 {
		t.Fatalf("expected 1 file-scanning error, but got %d", len(fileScanningErrors))
	}
	if len(netpols) != 0 {
		t.Fatalf("expected no policies, but got %d policies", len(netpols))
	}
}

func TestPoliciesSynthesizerAPIFailFast(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls")

	synthesizer := NewPoliciesSynthesizer(WithStopOnError())
	netpols, err := synthesizer.PoliciesFromFolderPath(dirPath)
	if err != nil {
		t.Fatalf("expected no fatal errors, but got %v", err)
	}
	fileScanningErrors := synthesizer.Errors()
	if len(fileScanningErrors) != 1 {
		t.Fatalf("expected 1 file-scanning error, but got %d", len(fileScanningErrors))
	}
	if len(netpols) != 0 {
		t.Fatalf("expected no policies, but got %d policies", len(netpols))
	}
}

func TestExtractConnectionsNoK8sResources(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "bad_yamls", "irrelevant_k8s_resources.yaml")
	args := getTestArgs(dirPath, "", false)
	conns, errs := extractConnections(args, false)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if len(conns) > 0 {
		t.Fatalf("expected no conns but got %d", len(conns))
	}
}

func TestExtractConnectionsNoK8sResourcesFailFast(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "bad_yamls")
	args := getTestArgs(dirPath, "", true)
	conns, errs := extractConnections(args, true)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if len(conns) > 0 {
		t.Fatalf("expected no conns but got %d", len(conns))
	}
}

func TestExtractConnectionsBadConfigMapRefs(t *testing.T) {
	testsDir := getTestsDir()
	dirPath := filepath.Join(testsDir, "bad_yamls", "bad_configmap_refs.yaml")
	args := getTestArgs(dirPath, "", false)
	conns, errs := extractConnections(args, false)
	if len(errs) != 3 {
		t.Fatalf("expected 3 errors but got %d", len(errs))
	}
	if len(conns) > 0 {
		t.Fatalf("expected no conns but got %d", len(conns))
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func getTestsDir() string {
	currentDir, _ := os.Getwd()
	return filepath.Join(currentDir, "..", "..", "tests")
}

func getTestArgs(dirPath, outFile string, netpols bool) common.InArgs {
	args := common.InArgs{}
	args.DirPath = &dirPath
	args.OutputFile = &outFile
	args.SynthNetpols = &netpols
	return args
}

func compareFiles(expectedFile, actualFile string) (bool, error) {
	expectedLines, err1 := readLines(expectedFile)
	actualLines, err2 := readLines(actualFile)
	if err1 != nil || err2 != nil {
		return false, errors.New("error reading lines from file")
	}
	if len(expectedLines) != len(actualLines) {
		fmt.Printf("Files line count is different: expected(%s): %d, actual(%s): %d",
			expectedFile, len(expectedLines), actualFile, len(actualLines))
		return false, nil
	}

	for i := 0; i < len(expectedLines); i++ {
		lineExpected := expectedLines[i]
		lineActual := actualLines[i]
		if lineExpected != lineActual && !strings.Contains(lineExpected, "\"filepath\"") {
			fmt.Printf("Gap in line %d: expected(%s): %s, actual(%s): %s", i, expectedFile, lineExpected, actualFile, lineActual)
			return false, nil
		}
	}
	return true, nil
}
