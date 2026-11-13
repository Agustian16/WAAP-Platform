// protogen compiles proto/**/*.proto with the pure-Go protocompile parser and runs protoc-gen-go and
// protoc-gen-go-grpc on the result, so no protoc binary is needed. Run from server/: go run ./tools/protogen
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	files := []string{"agent/v1/agent.proto"}
	c := protocompile.Compiler{Resolver: &protocompile.SourceResolver{ImportPaths: []string{"proto"}}}
	res, err := c.Compile(context.Background(), files...)
	check(err)
	var protos []*descriptorpb.FileDescriptorProto
	for _, f := range res {
		protos = append(protos, protodesc.ToFileDescriptorProto(f))
	}
	for _, plugin := range []string{"protoc-gen-go", "protoc-gen-go-grpc"} {
		req, err := proto.Marshal(&pluginpb.CodeGeneratorRequest{
			FileToGenerate: files, Parameter: proto.String("paths=source_relative"), ProtoFile: protos,
		})
		check(err)
		cmd := exec.Command(plugin)
		cmd.Stdin, cmd.Stderr = bytes.NewReader(req), os.Stderr
		out, err := cmd.Output()
		check(err)
		var resp pluginpb.CodeGeneratorResponse
		check(proto.Unmarshal(out, &resp))
		if resp.Error != nil {
			check(fmt.Errorf("%s: %s", plugin, *resp.Error))
		}
		for _, f := range resp.File {
			p := filepath.Join("gen", f.GetName())
			check(os.MkdirAll(filepath.Dir(p), 0o755))
			check(os.WriteFile(p, []byte(f.GetContent()), 0o644))
			fmt.Println("wrote", p)
		}
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
