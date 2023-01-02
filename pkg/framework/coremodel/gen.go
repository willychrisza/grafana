//go:build ignore
// +build ignore

//go:generate go run gen.go

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/load"

	"github.com/grafana/cuetsy"
	gcgen "github.com/grafana/grafana/pkg/codegen"
)

const sep = string(filepath.Separator)

var tsroot, cmroot, groot string

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not get working directory: %s", err)
		os.Exit(1)
	}

	// TODO this binds us to only having coremodels in a single directory. If we need more, compgen is the way
	groot = filepath.Dir(filepath.Dir(filepath.Dir(cwd))) // the working dir is <grafana_dir>/pkg/framework/coremodel. Going up 3 dirs we get the grafana root

	cmroot = filepath.Join(groot, "pkg", "coremodel")
	tsroot = filepath.Join(groot, "packages", "grafana-schema", "src")
}

// Generate Go and Typescript implementations for all coremodels, and populate the
// coremodel static registry.
func main() {
	if len(os.Args) > 1 {
		fmt.Fprintf(os.Stderr, "coremodel code generator does not currently accept any arguments\n, got %q", os.Args)
		os.Exit(1)
	}

	wd := gcgen.NewWriteDiffer()

	// TODO generating these is here temporarily until we make a more permanent home
	wdsh, err := genSharedSchemas(groot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TS gen error for shared schemas in %s: %w", filepath.Join(groot, "packages", "grafana-schema", "src", "schema"), err)
		os.Exit(1)
	}
	wd.Merge(wdsh)

	if _, set := os.LookupEnv("CODEGEN_VERIFY"); set {
		err = wd.Verify()
		if err != nil {
			fmt.Fprintf(os.Stderr, "generated code is not up to date:\n%s\nrun `make gen-cue` to regenerate\n\n", err)
			os.Exit(1)
		}
	} else {
		err = wd.Write()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while writing generated code to disk:\n%s\n", err)
			os.Exit(1)
		}
	}
}

func genSharedSchemas(groot string) (gcgen.WriteDiffer, error) {
	abspath := filepath.Join(groot, "packages", "grafana-schema", "src", "schema")
	cfg := &load.Config{
		ModuleRoot: groot,
		Module:     "github.com/grafana/grafana",
		Dir:        abspath,
	}

	bi := load.Instances(nil, cfg)
	if len(bi) > 1 {
		return nil, fmt.Errorf("loading CUE files in %s resulted in more than one instance", abspath)
	}

	ctx := cuecontext.New()
	v := ctx.BuildInstance(bi[0])
	if v.Err() != nil {
		return nil, fmt.Errorf("errors while building CUE in %s: %s", abspath, v.Err())
	}

	b, err := cuetsy.Generate(v, cuetsy.Config{
		Export: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TS: %w", err)
	}

	wd := gcgen.NewWriteDiffer()
	wd[filepath.Join(abspath, "mudball.gen.ts")] = append([]byte(`//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~  ~~~~~~~~~~~~~~~~~~~
// This file is autogenerated. DO NOT EDIT.
//
// To regenerate, run "make gen-cue" from the repository root.
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
`), b...)
	return wd, nil
}
