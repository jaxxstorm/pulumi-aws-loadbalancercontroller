package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	dotnetgen "github.com/pulumi/pulumi/pkg/v2/codegen/dotnet"
	gogen "github.com/pulumi/pulumi/pkg/v2/codegen/go"
	nodejsgen "github.com/pulumi/pulumi/pkg/v2/codegen/nodejs"
	pygen "github.com/pulumi/pulumi/pkg/v2/codegen/python"
	"github.com/pulumi/pulumi/pkg/v2/codegen/schema"
	"github.com/pulumi/pulumi/sdk/v2/go/common/util/contract"
)

const Tool = "pulumi-gen-awslbcontroller"

// Language is the SDK language.
type Language string

const (
	DotNet Language = "dotnet"
	Go     Language = "go"
	NodeJS Language = "nodejs"
	Python Language = "python"
	Schema Language = "schema"
)

func main() {
	printUsage := func() {
		fmt.Printf("Usage: %s <language> <out-dir> [schema-file] [version]\n", os.Args[0])
	}

	args := os.Args[1:]
	if len(args) < 2 {
		printUsage()
		os.Exit(1)
	}

	language, outdir := Language(args[0]), args[1]

	var schemaFile string
	var version string
	if language != Schema {
		if len(args) < 4 {
			printUsage()
			os.Exit(1)
		}
		schemaFile, version = args[2], args[3]
	}

	switch language {
	case DotNet:
		genDotNet(readSchema(schemaFile, version), outdir)
	case Go:
		genGo(readSchema(schemaFile, version), outdir)
	case NodeJS:
		genNodeJS(readSchema(schemaFile, version), outdir)
	case Python:
		genPython(readSchema(schemaFile, version), outdir)
	case Schema:
		pkgSpec := generateSchema()
		mustWritePulumiSchema(pkgSpec, outdir)
	default:
		panic(fmt.Sprintf("Unrecognized language %q", language))
	}
}

const awsVersion = "v3.28.0"

func awsRef(ref string) string {
	return fmt.Sprintf("/aws/%s/schema.json%s", awsVersion, ref)
}

// nolint: lll
func generateSchema() schema.PackageSpec {
	return schema.PackageSpec{
		Name:        "awslbcontroller",
		Description: "Pulumi Amazon Web Services (AWS) Kubernetes Load Balancer Controller Component",
		License:     "Apache-2.0",
		Keywords:    []string{"pulumi", "aws", "loadbalancercontroller"},
		Homepage:    "https://pulumi.com",
		Repository:  "https://github.com/jaxxstorm/pulumi-aws-loadbalancercontroller", // TODO
		Resources: map[string]schema.ResourceSpec{
			"awslbcontroller:index:awslbcontroller": {
				IsComponent: true,
				ObjectTypeSpec: schema.ObjectTypeSpec{
					Properties: map[string]schema.PropertySpec{
						"namespaceId": {
							TypeSpec:    schema.TypeSpec{Type: "string"},
							Description: "The ID of the namespace resources.",
						},
					},
					Required: []string{
						"namespaceId",
					},
				},
				InputProperties: map[string]schema.PropertySpec{
					"namespace": {
						TypeSpec: schema.TypeSpec{Type: "string"},
						Description: "Specifies the namespace to install your resources in",
					},
				},
			},
		},

		Types: map[string]schema.ComplexTypeSpec{},

		Language: map[string]json.RawMessage{
			"csharp": rawMessage(map[string]interface{}{
				"packageReferences": map[string]string{
					"Pulumi":     "2.*",
					"Pulumi.Aws": "3.*",
					"Pulumi.Kubernetes": "2.*",
				},
			}),
			"go": rawMessage(map[string]interface{}{
				"generateResourceContainerTypes": true,
				"importBasePath":                 "github.com/jaxxstorm/pulumi-aws-loadbalancercontroller/sdk/go/vpc",
			}),
			"nodejs": rawMessage(map[string]interface{}{
				"dependencies": map[string]string{
					"@pulumi/aws": "^3.28.0",
					"@pulumi/kubernetes": "^2.8.0",
				},
				"devDependencies": map[string]string{
					"typescript": "^3.7.0",
				},
				"packageName": "@jaxxstorm/pulumi-aws-loadbalancercontroller",
			}),
			"python": rawMessage(map[string]interface{}{
				"requires": map[string]string{
					"pulumi":     ">=2.20.0,<3.0.0",
					"pulumi-aws": ">=3.28.0,<4.0.0",
					"pulumi-kubernetes": ">v2.8.0,<3.0.0",
				},
				"readme": "Pulumi Amazon Web Services (AWS) Kubernetes Load Balancer Controller Component.",
			}),
		},
	}
}

func rawMessage(v interface{}) json.RawMessage {
	bytes, err := json.Marshal(v)
	contract.Assert(err == nil)
	return bytes
}

func readSchema(schemaPath string, version string) *schema.Package {
	// Read in, decode, and import the schema.
	schemaBytes, err := ioutil.ReadFile(schemaPath)
	if err != nil {
		panic(err)
	}

	var pkgSpec schema.PackageSpec
	if err = json.Unmarshal(schemaBytes, &pkgSpec); err != nil {
		panic(err)
	}
	pkgSpec.Version = version

	pkg, err := schema.ImportSpec(pkgSpec, nil)
	if err != nil {
		panic(err)
	}
	return pkg
}

func genDotNet(pkg *schema.Package, outdir string) {
	files, err := dotnetgen.GeneratePackage(Tool, pkg, map[string][]byte{})
	if err != nil {
		panic(err)
	}
	mustWriteFiles(outdir, files)
}

func genGo(pkg *schema.Package, outdir string) {
	files, err := gogen.GeneratePackage(Tool, pkg)
	if err != nil {
		panic(err)
	}
	mustWriteFiles(outdir, files)
}

func genNodeJS(pkg *schema.Package, outdir string) {
	files, err := nodejsgen.GeneratePackage(Tool, pkg, map[string][]byte{})
	if err != nil {
		panic(err)
	}
	mustWriteFiles(outdir, files)
}

func genPython(pkg *schema.Package, outdir string) {
	files, err := pygen.GeneratePackage(Tool, pkg, map[string][]byte{})
	if err != nil {
		panic(err)
	}
	mustWriteFiles(outdir, files)
}

func mustWriteFiles(rootDir string, files map[string][]byte) {
	for filename, contents := range files {
		mustWriteFile(rootDir, filename, contents)
	}
}

func mustWriteFile(rootDir, filename string, contents []byte) {
	outPath := filepath.Join(rootDir, filename)

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		panic(err)
	}
	err := ioutil.WriteFile(outPath, contents, 0600)
	if err != nil {
		panic(err)
	}
}

func mustWritePulumiSchema(pkgSpec schema.PackageSpec, outdir string) {
	schemaJSON, err := json.MarshalIndent(pkgSpec, "", "    ")
	if err != nil {
		panic(errors.Wrap(err, "marshaling Pulumi schema"))
	}
	mustWriteFile(outdir, "schema.json", schemaJSON)
}
