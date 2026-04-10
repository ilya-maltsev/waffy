// waffy-compile reads YAML profile files and generates the binary rule store.
//
// Usage:
//
//	waffy-compile --profiles /var/waffy/profiles --output /var/waffy/rules.bin
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/waffy-waf/waffy/compiler/internal/compiler"
	"github.com/waffy-waf/waffy/compiler/internal/profile"
)

func main() {
	profileDir := flag.String("profiles", "./profiles", "Directory containing YAML profile files")
	outputPath := flag.String("output", "./rules.bin", "Output path for compiled binary rule store")
	flag.Parse()

	fmt.Printf("waffy-compile: loading profiles from %s\n", *profileDir)

	profiles, err := profile.LoadProfileDir(*profileDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading profiles: %v\n", err)
		os.Exit(1)
	}

	if len(profiles) == 0 {
		fmt.Fprintf(os.Stderr, "no profiles found in %s\n", *profileDir)
		os.Exit(1)
	}

	fmt.Printf("  loaded %d location profile(s)\n", len(profiles))
	for _, p := range profiles {
		fmt.Printf("    %s %s — %d parameter rules\n",
			p.Method, p.Location, len(p.Parameters))
	}

	f, err := os.Create(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	c := compiler.New(profiles)
	if err := c.Compile(f); err != nil {
		fmt.Fprintf(os.Stderr, "error compiling rules: %v\n", err)
		os.Exit(1)
	}

	info, _ := f.Stat()
	fmt.Printf("\nCompiled rule store written to %s (%d bytes)\n", *outputPath, info.Size())
	fmt.Println("Next: copy to nginx server and reload (nginx -s reload)")
}
