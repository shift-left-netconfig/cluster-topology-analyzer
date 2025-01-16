/*
Copyright 2020- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"flag"
	"fmt"

	"github.com/np-guard/cluster-topology-analyzer/v2/pkg/analyzer"
)

type pathList []string

func (dp *pathList) String() string {
	return fmt.Sprintln(*dp)
}

func (dp *pathList) Set(path string) error {
	*dp = append(*dp, path)
	return nil
}

const (
	jsonFormat = "json"
	yamlFormat = "yaml"
)

type inArgs struct {
	DirPaths     pathList
	OutputFile   *string
	OutputFormat *string
	DNSPort      *int
	connsFile    *string
	SynthNetpols *bool
	Quiet        *bool
	Verbose      *bool
}

func parseInArgs(cmdlineArgs []string) (*inArgs, error) {
	args := inArgs{}
	flagset := flag.NewFlagSet("cluster-topology-analyzer", flag.ContinueOnError)
	flagset.Var(&args.DirPaths, "dirpath", "input directory path")
	args.OutputFile = flagset.String("outputfile", "", "file path to store results")
	args.OutputFormat = flagset.String("format", jsonFormat, "output format; must be either \"json\" or \"yaml\"")
	args.SynthNetpols = flagset.Bool("netpols", false, "whether to synthesize NetworkPolicies to allow only the discovered connections")
	args.DNSPort = flagset.Int("dnsport", analyzer.DefaultDNSPort, "DNS port to be used in egress rules of synthesized NetworkPolicies")
	args.connsFile = flagset.String("conns", "", "a file specifying connections to enable")
	args.Quiet = flagset.Bool("q", false, "runs quietly, reports only severe errors and results")
	args.Verbose = flagset.Bool("v", false, "runs with more informative messages printed to log")
	err := flagset.Parse(cmdlineArgs)
	if err != nil {
		return nil, err
	}

	if len(args.DirPaths) == 0 {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("missing parameter: dirpath")
	}
	if *args.Quiet && *args.Verbose {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("-q and -v cannot be specified together")
	}
	if *args.OutputFormat != jsonFormat && *args.OutputFormat != yamlFormat {
		flagset.PrintDefaults()
		return nil, fmt.Errorf("wrong output format %s; must be either json or yaml", *args.OutputFormat)
	}

	return &args, nil
}
