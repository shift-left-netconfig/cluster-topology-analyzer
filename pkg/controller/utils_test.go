package controller

import (
	"path/filepath"
	"testing"
)

func TestGetK8sDeploymentResourcesBadYamlDocument(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	objs, errs := getK8sDeploymentResources(dirPath, false)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if docID, err := errs[0].DocumentID(); docID != 6 || err != nil {
		t.Fatalf("expected bad Document ID to be 6 but got %d", errs[0].docID)
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 parsed file but got %d", len(objs))
	}
	if len(objs[0].DeployObjects) != 6 {
		t.Fatalf("expected 6 parsed objects but got %d", len(objs[0].DeployObjects))
	}
}

func TestGetK8sDeploymentResourcesBadYamlDocumentFailFast(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "document_with_syntax_error.yaml")
	objs, errs := getK8sDeploymentResources(dirPath, true)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if docID, err := errs[0].DocumentID(); docID != 6 || err != nil {
		t.Fatalf("expected bad Document ID to be 6 but got %d", errs[0].docID)
	}
	if len(objs) != 0 {
		t.Fatalf("expected no parsed file but got %d", len(objs))
	}
}

func TestGetK8sDeploymentResourcesNoK8sResource(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "not_a_k8s_resource.yaml")
	objs, errs := getK8sDeploymentResources(dirPath, false)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if len(objs) != 1 {
		t.Fatalf("expected 1 parsed file but got %d", len(objs))
	}
	if len(objs[0].DeployObjects) != 1 {
		t.Fatalf("expected 1 parsed object but got %d", len(objs[0].DeployObjects))
	}
}

func TestGetK8sDeploymentResourcesNoYAMLs(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "subdir2")
	objs, errs := getK8sDeploymentResources(dirPath, false)
	if len(errs) != 1 {
		t.Fatalf("expected one error but got %d", len(errs))
	}
	if len(objs) != 0 {
		t.Fatalf("expected no parsed files but got %d", len(objs))
	}
}

func TestGetK8sDeploymentResourcesBadDir(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	objs, errs := getK8sDeploymentResources(dirPath, false)
	if len(errs) != 1 {
		t.Fatalf("expected 1 errors but got %d", len(errs))
	}
	if len(objs) != 0 {
		t.Fatalf("expected no parsed files but got %d", len(objs))
	}
}

func TestGetK8sDeploymentResourcesBadDirFailFast(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls", "subdir3") // doesn't exist
	objs, errs := getK8sDeploymentResources(dirPath, true)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error but got %d", len(errs))
	}
	if len(objs) != 0 {
		t.Fatalf("expected no parsed files but got %d", len(objs))
	}
}

func TestSearchDeploymentManifests(t *testing.T) {
	dirPath := filepath.Join(getTestsDir(), "bad_yamls")
	yamlFiles, errs := searchDeploymentManifests(dirPath, false)
	if len(yamlFiles) != 5 {
		t.Fatalf("expected 5 yamls but got %d", len(yamlFiles))
	}
	if len(errs) > 0 {
		t.Fatalf("expected no errors but got %d", len(errs))
	}
}
