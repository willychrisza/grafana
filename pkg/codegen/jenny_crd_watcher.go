package codegen

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/grafana/codejen"
	"github.com/grafana/grafana/pkg/kindsys"
)

// CRDWatcherJenny generates WatcherWrapper implementations for a CRD.
func CRDWatcherJenny(path, tmplName, outputName string) OneToOne {
	return crdWatcherJenny{
		tmplName:   tmplName,
		outputName: outputName,
		parentpath: path,
	}
}

type crdWatcherJenny struct {
	tmplName   string
	outputName string
	parentpath string
}

func (j crdWatcherJenny) JennyName() string {
	return "CRDWatcherJenny"
}

func (j crdWatcherJenny) Generate(kind kindsys.Kind) (*codejen.File, error) {
	_, isCore := kind.(kindsys.Core)
	_, isCustom := kind.(kindsys.Core)
	if !(isCore || isCustom) {
		return nil, nil
	}

	buf := new(bytes.Buffer)
	if err := tmpls.Lookup(j.tmplName).Execute(buf, kind); err != nil {
		return nil, fmt.Errorf("failed executing crd watcher template: %w", err)
	}

	name := kind.Props().Common().MachineName
	path := filepath.Join(j.parentpath, name, j.outputName)
	b, err := postprocessGoFile(genGoFile{
		path: path,
		in:   buf.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	return codejen.NewFile(path, b, j), nil
}
