// Command oracle records how hashicorp/hcl itself reads each case in native.json and json.json, so
// tests/chock_scan/test_hcl_oracle.py can hold chock_scan.hcl and hcl_json to HCL's answers.
// Regenerate (needs Go; not run by CI): cd tests/chock_scan/oracle && go run . native.json json.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// Case is one input; HCL is filled in: "ERR" if HCL refuses it, else one line per attribute and block.
type Case struct {
	Name   string         `json:"name"`
	Src    string         `json:"src"`
	Nested map[string]int `json:"nested,omitempty"` // json only: nested block types to read, with label counts
	Attrs  []string       `json:"attrs,omitempty"`  // json only: the argument names to read, as a provider schema would
	HCL    any            `json:"hcl"`
}

var top = map[string]int{"resource": 2, "data": 2, "module": 1, "provider": 1, "variable": 1, "output": 1, "check": 1, "terraform": 0, "locals": 0}

func value(expr hcl.Expression) string {
	v, d := expr.Value(&hcl.EvalContext{}) // a context, as Terraform gives: JSON strings are then templates
	if d.HasErrors() || !v.IsWhollyKnown() {
		return "C"
	}
	j, err := ctyjson.SimpleJSONValue{Value: v}.MarshalJSON()
	if err != nil {
		return "C"
	}
	return string(j)
}

func attrs(m hcl.Attributes, path string, out *[]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		*out = append(*out, fmt.Sprintf("%s|A|%s|%s", path, k, value(m[k].Expr)))
	}
}

func block(b *hcl.Block, i int, path string) string {
	labels, _ := json.Marshal(append([]string{}, b.Labels...))
	return fmt.Sprintf("%s/%d:%s%s", path, i, b.Type, labels)
}

func native(b *hclsyntax.Body, path string, out *[]string) {
	m := hcl.Attributes{}
	for k, a := range b.Attributes {
		m[k] = a.AsHCLAttribute()
	}
	attrs(m, path, out)
	for i, bl := range b.Blocks {
		p := block(bl.AsHCLBlock(), i, path)
		*out = append(*out, p+"|B")
		native(bl.Body, p, out)
	}
}

func schema(labels map[string]int, names ...string) *hcl.BodySchema {
	s := &hcl.BodySchema{}
	for _, n := range names {
		s.Attributes = append(s.Attributes, hcl.AttributeSchema{Name: n})
	}
	types := make([]string, 0, len(labels))
	for k := range labels {
		types = append(types, k)
	}
	sort.Strings(types)
	for _, k := range types {
		s.Blocks = append(s.Blocks, hcl.BlockHeaderSchema{Type: k, LabelNames: make([]string, labels[k])})
	}
	return s
}

// jsonBody reads a body the way Terraform does: PartialContent against a schema (never JustAttributes).
func jsonBody(b hcl.Body, c *Case, path string, out *[]string) hcl.Diagnostics {
	content, _, d := b.PartialContent(schema(c.Nested, c.Attrs...))
	if d.HasErrors() {
		return d
	}
	attrs(content.Attributes, path, out)
	for i, bl := range content.Blocks {
		p := block(bl, i, path)
		*out = append(*out, p+"|B")
		if d := jsonBody(bl.Body, c, p, out); d.HasErrors() {
			return d
		}
	}
	return nil
}

func run(c *Case, syntax string) {
	out := []string{}
	if syntax == "native" {
		f, d := hclsyntax.ParseConfig([]byte(c.Src), "x.tf", hcl.InitialPos)
		if d.HasErrors() {
			c.HCL = "ERR"
			return
		}
		native(f.Body.(*hclsyntax.Body), "", &out)
	} else {
		f, d := hcljson.Parse([]byte(c.Src), "x.tf.json")
		if d.HasErrors() {
			c.HCL = "ERR"
			return
		}
		root, d := f.Body.Content(schema(top))
		if d.HasErrors() {
			c.HCL = "ERR"
			return
		}
		for i, bl := range root.Blocks {
			p := block(bl, i, "")
			out = append(out, p+"|B")
			if d := jsonBody(bl.Body, c, p, &out); d.HasErrors() {
				c.HCL = "ERR"
				return
			}
		}
	}
	c.HCL = out
}

func main() {
	for _, file := range os.Args[1:] {
		data, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}
		var cases []Case
		if err := json.Unmarshal(data, &cases); err != nil {
			panic(err)
		}
		syntax := map[string]string{"native.json": "native", "json.json": "json"}[file]
		for i := range cases {
			run(&cases[i], syntax)
		}
		data, _ = json.MarshalIndent(cases, "", " ")
		if err := os.WriteFile(file, append(data, '\n'), 0o644); err != nil {
			panic(err)
		}
	}
}
