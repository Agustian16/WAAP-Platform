// corazium-ctl validates a coraza-policy.yaml in CI (FR-5.3): the same checks the console runs, with the real
// Coraza parser. Exit status 0 means the policy is deployable.
//
//	corazium-ctl validate coraza-policy.yaml
package main

import (
	"fmt"
	"os"

	"github.com/Agustian16/WAAP-Platform/server/internal/api"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: corazium-ctl validate <coraza-policy.yaml>")
		os.Exit(2)
	}
	text, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	errs, _ := api.ValidatePolicy(string(text), nil)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "error:", e)
	}
	if len(errs) > 0 {
		os.Exit(1)
	}
	fmt.Println("policy is valid")
}
