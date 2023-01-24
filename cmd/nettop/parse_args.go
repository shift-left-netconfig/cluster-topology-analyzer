package main

import (
	"flag"
	"fmt"
)

type PathList []string

func (dp *PathList) String() string {
	return fmt.Sprintln(*dp)
}

func (dp *PathList) Set(path string) error {
	*dp = append(*dp, path)
	return nil
}

const (
	JSONFormat = "json"
	YamlFormat = "yaml"
)

type InArgs struct {
	DirPaths     PathList
	OutputFile   *string
	OutputFormat *string
	SynthNetpols *bool
	Quiet        *bool
	Verbose      *bool
}

func ParseInArgs(args *InArgs) error {
	flag.Var(&args.DirPaths, "dirpath", "input directory path")
	args.OutputFile = flag.String("outputfile", "", "file path to store results")
	args.OutputFormat = flag.String("format", JSONFormat, "output format; must be either \"json\" or \"yaml\"")
	args.SynthNetpols = flag.Bool("netpols", false, "whether to synthesize NetworkPolicies to allow only the discovered connections")
	args.Quiet = flag.Bool("q", false, "runs quietly, reports only severe errors and results")
	args.Verbose = flag.Bool("v", false, "runs with more informative messages printed to log")
	flag.Parse()

	if len(args.DirPaths) == 0 {
		flag.PrintDefaults()
		return fmt.Errorf("missing parameter: dirpath")
	}
	if *args.Quiet && *args.Verbose {
		flag.PrintDefaults()
		return fmt.Errorf("-q and -v cannot be specified together")
	}
	if *args.OutputFormat != JSONFormat && *args.OutputFormat != YamlFormat {
		flag.PrintDefaults()
		return fmt.Errorf("wrong output format %s; must be either json or yaml", *args.OutputFormat)
	}

	return nil
}
