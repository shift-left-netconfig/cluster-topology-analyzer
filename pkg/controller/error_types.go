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

// constructs a FileProcessingError object and prints an error/warning to the log
func newFileProcessingError(origErr error, msg, filePath string, lineNum, docID int, fatal, severe bool) *FileProcessingError {
	err := errors.New(msg)
	if origErr != nil {
		err = fmt.Errorf("%s: %w", msg, err)
	}
	fpe := FileProcessingError{err, filePath, lineNum, docID, fatal, severe}

	logMsg := msg
	location := fpe.Location()
	if location != "" {
		logMsg = fmt.Sprintf("%s %s", location, msg)
	}
	if fpe.IsSevere() || fpe.IsFatal() {
		activeLogger.Errorf(origErr, logMsg)
	} else {
		activeLogger.Warnf(logMsg)
	}

	return &fpe
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

func (e *FileProcessingError) DocumentID() (int, error) {
	if e.docID < 0 {
		return -1, errors.New("no document ID is available for this error")
	}
	return e.docID, nil
}

func (e *FileProcessingError) Location() string {
	if e.filePath == "" {
		return ""
	}

	suffix := ""
	if e.lineNum > 0 {
		suffix = fmt.Sprintf(", line: %d", e.LineNo())
	}
	if did, err := e.DocumentID(); err == nil {
		suffix += fmt.Sprintf(", document: %d%s", did, suffix)
	}
	return fmt.Sprintf("in file: %s%s", e.File(), suffix)
}

func (e *FileProcessingError) IsFatal() bool {
	return e.fatal
}

func (e *FileProcessingError) IsSevere() bool {
	return e.severe
}

// --------  Constructors for specific error types ----------------

func noYamlsFound() *FileProcessingError {
	return newFileProcessingError(nil, "no yaml files found", "", 0, -1, false, false)
}

func noK8sResourcesFound() *FileProcessingError {
	return newFileProcessingError(nil, "no relevant Kubernetes resources found", "", 0, -1, false, false)
}

func configMapNotFound(cfgMapName, resourceName string) *FileProcessingError {
	msg := fmt.Sprintf("configmap %s not found (referenced by %s)", cfgMapName, resourceName)
	return newFileProcessingError(nil, msg, "", 0, -1, false, false)
}

func configMapKeyNotFound(cfgMapName, cfgMapKey, resourceName string) *FileProcessingError {
	msg := fmt.Sprintf("configmap %s does not have key %s (referenced by %s)", cfgMapName, cfgMapKey, resourceName)
	return newFileProcessingError(nil, msg, "", 0, -1, false, false)
}

func failedScanningResource(resourceType, filePath string, err error) *FileProcessingError {
	msg := fmt.Sprintf("error scanning %s resource", resourceType)
	return newFileProcessingError(err, msg, filePath, 0, -1, false, false)
}

func notK8sResource(filePath string, docID int, err error) *FileProcessingError {
	return newFileProcessingError(err, "Yaml document is not a K8s resource", filePath, 0, docID, false, false)
}

func malformedYamlDoc(filePath string, lineNum, docID int, err error) *FileProcessingError {
	return newFileProcessingError(err, "YAML document is malformed", filePath, lineNum, docID, false, true)
}

func failedReadingFile(filePath string, err error) *FileProcessingError {
	return newFileProcessingError(err, "error reading file", filePath, 0, -1, false, true)
}

func failedAccessingDir(dirPath string, err error, isSubDir bool) *FileProcessingError {
	return newFileProcessingError(err, "error accessing directory", dirPath, 0, -1, !isSubDir, true)
}

func failedWalkDir(dirPath string, err error) *FileProcessingError {
	return newFileProcessingError(err, "error scanning directory", dirPath, 0, -1, true, true)
}
