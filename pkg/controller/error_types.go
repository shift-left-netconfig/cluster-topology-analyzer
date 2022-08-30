package controller

import (
	"errors"
	"fmt"
)

type FileProcessingError struct {
	err      error
	filePath string
	lineNum  int  // the line number in filePath where the error originates from (1-based, 0 means unknown)
	docID    int  // the number of the YAML document where the error originates from (0-based, -1 means unknown)
	fatal    bool // a fatal error is not recoverable. Outputs should not be used
	severe   bool // a severe error is recoverable. However, outputs should be used with care
}

func newFileProcessingError(msg, filePath string, lineNum, docID int, fatal, severe bool) *FileProcessingError {
	errorMsg := fmt.Sprintf("In file %s", filePath)
	if lineNum > 0 {
		errorMsg += fmt.Sprintf(", line %d", lineNum)
	}
	if docID >= 0 {
		errorMsg += fmt.Sprintf(", document %d", docID)
	}
	errorMsg += fmt.Sprintf(": %s", msg)
	err := errors.New(errorMsg)
	return &FileProcessingError{err, filePath, lineNum, docID, fatal, severe}
}

func (e *FileProcessingError) Error() error {
	return e.err
}

func (e *FileProcessingError) File() string {
	return e.filePath
}

func (e *FileProcessingError) LineNo() int {
	return e.lineNum
}

func (e *FileProcessingError) DocumentID() int {
	return e.docID
}

func (e *FileProcessingError) IsFatal() bool {
	return e.fatal
}

func (e *FileProcessingError) IsSevere() bool {
	return e.severe
}

func noYamlsFound() *FileProcessingError {
	return newFileProcessingError("no yaml files found", "", 0, -1, false, false)
}

func noK8sResourcesFound() *FileProcessingError {
	return newFileProcessingError("no relevant Kubernetes resources found", "", 0, -1, false, false)
}

func configMapNotFound(cfgMapName, resourceName string) *FileProcessingError {
	msg := fmt.Sprintf("configmap %s not found (referenced by %s)", cfgMapName, resourceName)
	return newFileProcessingError(msg, "", 0, -1, false, false)
}

func configMapKeyNotFound(cfgMapName, cfgMapKey, resourceName string) *FileProcessingError {
	msg := fmt.Sprintf("configmap %s does not have key %s (referenced by %s)", cfgMapName, cfgMapKey, resourceName)
	return newFileProcessingError(msg, "", 0, -1, false, false)
}

func failedScanningResource(resourceType, filePath string, err error) *FileProcessingError {
	msg := fmt.Sprintf("error scanning %s resource: %v", resourceType, err)
	return newFileProcessingError(msg, filePath, 0, -1, false, false)
}

func notK8sResource(filePath string, docId int, err error) *FileProcessingError {
	msg := fmt.Sprintf("Yaml document is not a K8s resource: %v", err)
	return newFileProcessingError(msg, filePath, 0, docId, false, false)
}

func malformedYamlDoc(filePath string, docId int, err error) *FileProcessingError {
	msg := fmt.Sprintf("YAML document is malformed: %v", err)
	return newFileProcessingError(msg, filePath, 0, docId, false, true)
}

func failedReadingFile(filePath string, err error) *FileProcessingError {
	msg := fmt.Sprintf("error reading file: %v", err)
	return newFileProcessingError(msg, filePath, 0, -1, false, true)
}

func failedAccessingDir(dirPath string, err error, isSubDir bool) *FileProcessingError {
	msg := fmt.Sprintf("error accessing directory: %v", err)
	return newFileProcessingError(msg, dirPath, 0, -1, isSubDir, true)
}

func failedWalkDir(dirPath string, err error) *FileProcessingError {
	msg := fmt.Sprintf("error scanning directory: %v", err)
	return newFileProcessingError(msg, dirPath, 0, -1, true, true)
}
