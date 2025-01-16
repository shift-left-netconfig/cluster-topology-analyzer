package analyzer

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
)

func TestSelector(t *testing.T) {
	testStr := "key1=val1, key2=val2"
	reqs, err := labels.ParseToRequirements(testStr)
	if err != nil {
		t.Fatalf("Conversion error: %v", err)
	}

	res := map[string]string{}
	for _, req := range reqs {
		if req.Operator() != selection.Equals {
			t.Fatalf("Wrong operator: %s", req.Operator())
		}
		res[req.Key()] = req.Values().List()[0]
	}

	t.Logf("labels: %v", res)
}

func TestConnectionsFile(t *testing.T) {
	logger := NewDefaultLogger()
	sockshopDir := filepath.Join(getTestsDir(), "sockshop")
	manifestsDir := filepath.Join(sockshopDir, "manifests")
	mf := manifestFinder{logger, false, filepath.WalkDir}
	manifestFiles, fileErrors := mf.searchForManifestsInDirs([]string{manifestsDir})
	require.Empty(t, fileErrors)

	resAcc := newResourceAccumulator(logger, false)
	parseErrors := resAcc.parseK8sYamls(manifestFiles)
	require.Empty(t, parseErrors)

	ce := connectionExtractor{workloads: resAcc.workloads, services: resAcc.services, logger: logger}
	connections := ce.discoverConnections()
	require.NotEmpty(t, connections)
	connFilePath := filepath.Join(sockshopDir, "connections.txt")
	fileConns, err := ce.connectionsFromFile(connFilePath)
	require.Nil(t, err)
	require.Len(t, fileConns, 15)
}
