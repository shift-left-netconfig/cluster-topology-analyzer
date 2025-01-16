/*
Copyright 2020- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/np-guard/cluster-topology-analyzer/v2/pkg/analyzer"
)

func writeBufToFile(filepath string, buf []byte) error {
	fp, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", filepath, err)
	}
	_, err = fp.Write(buf)
	if err != nil {
		return fmt.Errorf("error writing to file %s: %w", filepath, err)
	}
	fp.Close()
	return nil
}

func yamlMarshalUsingJSON(content interface{}) ([]byte, error) {
	// Directly marshaling content into YAML, results in malformed Kubernetes resources.
	// This is because K8s NetworkPolicy struct has json field tags, but no yaml field tags (also true for other resources).
	// The (somewhat ugly) solution is to first marshal content to json, unmarshal to an interface{} var and marshal to yaml
	buf, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}

	var contentFromJSON interface{}
	err = json.Unmarshal(buf, &contentFromJSON)
	if err != nil {
		return nil, err
	}

	buf, err = yaml.Marshal(contentFromJSON)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func writeContent(outputFile, outputFormat string, content interface{}) error {
	var buf []byte
	var err error
	if outputFormat == yamlFormat {
		buf, err = yamlMarshalUsingJSON(content)
	} else {
		const indent = "    "
		buf, err = json.MarshalIndent(content, "", indent)
	}
	if err != nil {
		return err
	}

	if outputFile != "" {
		return writeBufToFile(outputFile, buf)
	}

	fmt.Println(string(buf))
	return nil
}

// returns verbosity level based on the -q and -v switches
func getVerbosity(args *inArgs) analyzer.Verbosity {
	verbosity := analyzer.MediumVerbosity
	if *args.Quiet {
		verbosity = analyzer.LowVerbosity
	} else if *args.Verbose {
		verbosity = analyzer.HighVerbosity
	}
	return verbosity
}

// Based on the arguments it is given, scans all YAML files,
// detects all required connection between resources and outputs a json connectivity report
// (or NetworkPolicies to allow only this connectivity)
func detectTopology(args *inArgs) error {
	logger := analyzer.NewDefaultLoggerWithVerbosity(getVerbosity(args))
	opts := []analyzer.PoliciesSynthesizerOption{analyzer.WithLogger(logger), analyzer.WithDNSPort(*args.DNSPort)}
	if *args.connsFile != "" {
		opts = append(opts, analyzer.WithConnectionsFile(*args.connsFile))
	}
	synth := analyzer.NewPoliciesSynthesizer(opts...)

	var content interface{}
	if args.SynthNetpols != nil && *args.SynthNetpols {
		policies, synthesisErr := synth.PoliciesFromFolderPaths(args.DirPaths)
		if synthesisErr != nil {
			logger.Errorf(synthesisErr, "error synthesizing policies")
			return synthesisErr
		}
		content = analyzer.NetpolListFromNetpolSlice(policies)
	} else {
		var err error
		content, err = synth.ConnectionsFromFolderPaths(args.DirPaths)
		if err != nil {
			logger.Errorf(err, "error extracting connections")
			return err
		}
	}

	if err := writeContent(*args.OutputFile, *args.OutputFormat, content); err != nil {
		logger.Errorf(err, "error writing results")
		return err
	}

	return nil
}

// The actual main function
// Takes command-line flags and returns an error rather than exiting, so it can be more easily used in testing
func _main(cmdlineArgs []string) error {
	inArgs, err := parseInArgs(cmdlineArgs)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("error parsing arguments: %w", err)
	}

	err = detectTopology(inArgs)
	if err != nil {
		return fmt.Errorf("error running topology analysis: %w", err)
	}
	return nil
}

func main() {
	err := _main(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v. exiting...", err)
		os.Exit(1)
	}
}
