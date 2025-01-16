/*
Copyright 2020- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// The analyzer package of cluster-topology-analyzer discovers the connectivity of a Kubernetes application
// by analyzing its YAML manifests and looking for network addresses that match. It can output a set of
// discovered connections or even Kubernetes NetworkPolicies to allow only these connections. For more
// information, see https://github.com/np-guard/cluster-topology-analyzer.
package analyzer

import (
	"io/fs"
	"path/filepath"
	"slices"

	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/cli-runtime/pkg/resource"
)

const (
	DefaultDNSPort = 53 // DefaultDNSPort is the default DNS port to use in the generated policies
)

// WalkFunction is a function for recursively scanning a directory, in the spirit of Go's native filepath.WalkDir()
// See https://pkg.go.dev/path/filepath#WalkDir for full description on how such a function should work
type WalkFunction func(root string, fn fs.WalkDirFunc) error

// A PoliciesSynthesizer provides API to recursively scan a directory for Kubernetes resources
// and extract the required connectivity between the workloads of the K8s application managed in this directory.
// It is possible to get either a slice with all the discovered connections or a slice with K8s NetworkPolicies
// that allow only the discovered connections and nothing more.
type PoliciesSynthesizer struct {
	logger          Logger
	stopOnError     bool
	walkFn          WalkFunction
	dnsPort         intstr.IntOrString
	connectionsFile string

	errors []FileProcessingError
}

// PoliciesSynthesizerOption is the type for specifying options for PoliciesSynthesizer,
// using Golang's Options Pattern (https://golang.cafe/blog/golang-functional-options-pattern.html).
type PoliciesSynthesizerOption func(*PoliciesSynthesizer)

// WithWalkFn is a functional option, allowing user to provide their own dir-scanning function.
// The function will be used when searching for YAML files; it must have the same signature as filepath.WalkDir.
func WithWalkFn(walkFn WalkFunction) PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.walkFn = walkFn
	}
}

// WithLogger is a functional option which sets the logger for a PoliciesSynthesizer to use.
// The provided logger must conform with the package's Logger interface.
func WithLogger(logger Logger) PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.logger = logger
	}
}

// WithStopOnError is a functional option which directs PoliciesSynthesizer to stop any processing after the
// first severe error.
func WithStopOnError() PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.stopOnError = true
	}
}

// WithDNSPort is a functional option to set the DNS port in the generated policies to a non-default integer value
func WithDNSPort(dnsPort int) PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.dnsPort = intstr.FromInt(dnsPort)
	}
}

// WithDNSNamedPort is a functional option to set the DNS port in the generated policies to a specific named port
func WithDNSNamedPort(dnsPort string) PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.dnsPort = intstr.FromString(dnsPort)
	}
}

func WithConnectionsFile(filename string) PoliciesSynthesizerOption {
	return func(p *PoliciesSynthesizer) {
		p.connectionsFile = filename
	}
}

// NewPoliciesSynthesizer creates a new instance of PoliciesSynthesizer, and applies the provided functional options.
func NewPoliciesSynthesizer(options ...PoliciesSynthesizerOption) *PoliciesSynthesizer {
	// object with default behavior options
	ps := &PoliciesSynthesizer{
		logger:      NewDefaultLogger(),
		stopOnError: false,
		walkFn:      filepath.WalkDir,
		dnsPort:     intstr.FromInt(DefaultDNSPort),
		errors:      []FileProcessingError{},
	}
	for _, o := range options {
		o(ps)
	}
	return ps
}

// Errors returns a slice of FileProcessingError with all warnings and errors encountered during processing.
func (ps *PoliciesSynthesizer) Errors() []FileProcessingError {
	return ps.errors
}

// ErrorPtrs returns a slice of pointers to FileProcessingError with all warnings and errors encountered during processing.
// Might be easier to use than Errors() if the returned slice is to be used as a slice of interfaces.
func (ps *PoliciesSynthesizer) ErrorPtrs() []*FileProcessingError {
	ret := make([]*FileProcessingError, len(ps.errors))
	for idx := range ps.errors {
		ret[idx] = &ps.errors[idx]
	}
	return ret
}

// PoliciesFromInfos returns a slice of Kubernetes NetworkPolicies that allow only the connections discovered
// while processing K8s resources in the given slice of Info objects.
func (ps *PoliciesSynthesizer) PoliciesFromInfos(infos []*resource.Info) ([]*networking.NetworkPolicy, error) {
	resources, connections, errs := ps.extractConnectionsFromInfos(infos)
	policies := []*networking.NetworkPolicy{}
	if !stopProcessing(ps.stopOnError, errs) {
		policies = ps.synthNetpols(resources, connections)
	}

	ps.errors = errs
	if err := hasFatalError(errs); err != nil {
		return nil, err
	}

	return policies, nil
}

// PoliciesFromFolderPath returns a slice of Kubernetes NetworkPolicies that allow only the connections discovered
// while processing K8s resources under the provided directory or one of its subdirectories (recursively).
func (ps *PoliciesSynthesizer) PoliciesFromFolderPath(dirPath string) ([]*networking.NetworkPolicy, error) {
	return ps.PoliciesFromFolderPaths([]string{dirPath})
}

// PoliciesFromFolderPaths returns a slice of Kubernetes NetworkPolicies that allow only the connections discovered
// while processing K8s resources under the provided directories or one of their subdirectories (recursively).
func (ps *PoliciesSynthesizer) PoliciesFromFolderPaths(dirPaths []string) ([]*networking.NetworkPolicy, error) {
	resources, connections, errs := ps.extractConnectionsFromFolderPaths(dirPaths)
	policies := []*networking.NetworkPolicy{}
	if !stopProcessing(ps.stopOnError, errs) {
		policies = ps.synthNetpols(resources, connections)
	}

	ps.errors = errs
	if err := hasFatalError(errs); err != nil {
		return nil, err
	}

	return policies, nil
}

// ConnectionsFromInfos returns a slice of Connections, listing the connections discovered
// while processing the K8s resources provided as a slice of Info objects.
func (ps *PoliciesSynthesizer) ConnectionsFromInfos(infos []*resource.Info) ([]*Connections, error) {
	_, connections, errs := ps.extractConnectionsFromInfos(infos)
	ps.errors = errs
	if err := hasFatalError(errs); err != nil {
		return nil, err
	}

	return connections, nil
}

// ConnectionsFromFolderPath returns a slice of Connections, listing the connections discovered
// while processing K8s resources under the provided directory or one of its subdirectories (recursively).
func (ps *PoliciesSynthesizer) ConnectionsFromFolderPath(dirPath string) ([]*Connections, error) {
	return ps.ConnectionsFromFolderPaths([]string{dirPath})
}

// ConnectionsFromFolderPaths returns a slice of Connections, listing the connections discovered
// while processing K8s resources under the provided directories or one of their subdirectories (recursively).
func (ps *PoliciesSynthesizer) ConnectionsFromFolderPaths(dirPaths []string) ([]*Connections, error) {
	_, connections, errs := ps.extractConnectionsFromFolderPaths(dirPaths)
	ps.errors = errs
	if err := hasFatalError(errs); err != nil {
		return nil, err
	}

	return connections, nil
}

func (ps *PoliciesSynthesizer) extractConnectionsFromInfos(infos []*resource.Info) (
	[]*Resource, []*Connections, []FileProcessingError) {
	resAcc := newResourceAccumulator(ps.logger, ps.stopOnError)
	parseErrors := resAcc.parseInfos(infos)
	if stopProcessing(ps.stopOnError, parseErrors) {
		return nil, nil, parseErrors
	}

	wls, conns, errs := ps.extractConnections(resAcc)
	errs = append(parseErrors, errs...)
	return wls, conns, errs
}

// Scans the given directories for YAMLs with k8s resources and extracts required connections between workloads
func (ps *PoliciesSynthesizer) extractConnectionsFromFolderPaths(dirPaths []string) (
	[]*Resource, []*Connections, []FileProcessingError) {
	// Find all manifest YAML files
	mf := manifestFinder{ps.logger, ps.stopOnError, ps.walkFn}
	manifestFiles, fileErrors := mf.searchForManifestsInDirs(dirPaths)
	if stopProcessing(ps.stopOnError, fileErrors) {
		return nil, nil, fileErrors
	}

	// Parse YAMLs and extract relevant resources
	resAcc := newResourceAccumulator(ps.logger, ps.stopOnError)
	parseErrors := resAcc.parseK8sYamls(manifestFiles)
	fileErrors = append(fileErrors, parseErrors...)
	if stopProcessing(ps.stopOnError, fileErrors) {
		return nil, nil, fileErrors
	}

	// discover connections from the set of resources
	wls, conns, errs := ps.extractConnections(resAcc)
	fileErrors = append(fileErrors, errs...)
	return wls, conns, fileErrors
}

func (ps *PoliciesSynthesizer) extractConnections(resAcc *resourceAccumulator) (
	[]*Resource, []*Connections, []FileProcessingError) {
	if len(resAcc.workloads) == 0 {
		return nil, nil, appendAndLogNewError(nil, noK8sResourcesFound(), ps.logger)
	}

	// Inline configmaps values as workload envs
	fileErrors := resAcc.inlineConfigMapRefsAsEnvs()
	if stopProcessing(ps.stopOnError, fileErrors) {
		return nil, nil, fileErrors
	}

	resAcc.exposeServices()

	// Discover all connections between resources
	ce := connectionExtractor{workloads: resAcc.workloads, services: resAcc.services, logger: ps.logger}
	connections := ce.discoverConnections()

	// If user specified a file with extra connections, add them too
	if ps.connectionsFile != "" {
		fileConns, err := ce.connectionsFromFile(ps.connectionsFile)
		if err != nil {
			fpErr := failedReadingFile(ps.connectionsFile, err)
			return nil, nil, appendAndLogNewError(fileErrors, fpErr, ps.logger)
		}
		connections = slices.Concat(connections, fileConns)
	}
	return resAcc.workloads, connections, fileErrors
}

func hasFatalError(errs []FileProcessingError) error {
	for idx := range errs {
		if errs[idx].IsFatal() {
			return errs[idx].Error()
		}
	}
	return nil
}
