// waffy-ctl is the management CLI for waffy.
//
// Usage:
//
//	waffy-ctl rules show /api/v1/users POST
//	waffy-ctl rules list --store /var/waffy/rules.bin
//	waffy-ctl compile --profiles /var/waffy/profiles --output /var/waffy/rules.bin
//	waffy-ctl reload --pid /var/run/nginx.pid
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/waffy-waf/waffy/compiler/internal/profile"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "rules":
		cmdRules(os.Args[2:])
	case "compile":
		fmt.Println("Use waffy-compile binary for compilation.")
		fmt.Println("  waffy-compile --profiles ./profiles --output ./rules.bin")
	case "reload":
		cmdReload(os.Args[2:])
	case "version":
		fmt.Println("waffy-ctl v0.1.0")
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("waffy-ctl — waffy management CLI")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  rules show <location> <method>  Show rules for a location")
	fmt.Println("  rules list --dir <profiles_dir> List all profiled locations")
	fmt.Println("  compile                         Compile profiles to binary store")
	fmt.Println("  reload --pid <nginx_pid_file>   Hot-reload rules in nginx")
	fmt.Println("  version                         Show version")
}

func cmdRules(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: waffy-ctl rules [show|list] ...")
		return
	}

	switch args[0] {
	case "list":
		dir := "./profiles"
		for i, a := range args {
			if a == "--dir" && i+1 < len(args) {
				dir = args[i+1]
			}
		}
		profiles, err := profile.LoadProfileDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%-8s %-40s %s\n", "METHOD", "LOCATION", "PARAMS")
		fmt.Println(strings.Repeat("-", 70))
		for _, p := range profiles {
			fmt.Printf("%-8s %-40s %d\n", p.Method, p.Location, len(p.Parameters))
		}

	case "show":
		if len(args) < 3 {
			fmt.Println("Usage: waffy-ctl rules show <location> <method>")
			return
		}
		location := args[1]
		method := strings.ToUpper(args[2])

		dir := "./profiles"
		for i, a := range args {
			if a == "--dir" && i+1 < len(args) {
				dir = args[i+1]
			}
		}

		profiles, err := profile.LoadProfileDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		for _, p := range profiles {
			if p.Location == location && strings.ToUpper(p.Method) == method {
				fmt.Printf("Location: %s %s\n", p.Method, p.Location)
				fmt.Printf("Strict mode: %v\n", p.StrictMode)
				if len(p.ContentTypes) > 0 {
					fmt.Printf("Content types: %s\n", strings.Join(p.ContentTypes, ", "))
				}
				fmt.Printf("\nParameters (%d):\n", len(p.Parameters))
				for _, param := range p.Parameters {
					req := "optional"
					if param.Required {
						req = "REQUIRED"
					}
					fmt.Printf("  %-25s %-10s %-8s %s\n",
						param.Name, param.Type, param.Source, req)
					if param.Constraints.Regex != "" {
						fmt.Printf("    regex: %s\n", param.Constraints.Regex)
					}
					if len(param.Constraints.Values) > 0 {
						fmt.Printf("    values: [%s]\n",
							strings.Join(param.Constraints.Values, ", "))
					}
					if param.Constraints.Min != nil || param.Constraints.Max != nil {
						fmt.Printf("    range: [%v, %v]\n",
							param.Constraints.Min, param.Constraints.Max)
					}
				}
				return
			}
		}
		fmt.Fprintf(os.Stderr, "no profile found for %s %s\n", method, location)

	default:
		fmt.Printf("unknown rules subcommand: %s\n", args[0])
	}
}

func cmdReload(args []string) {
	pidFile := "/var/run/nginx.pid"
	for i, a := range args {
		if a == "--pid" && i+1 < len(args) {
			pidFile = args[i+1]
		}
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading pid file %s: %v\n", pidFile, err)
		fmt.Println("Hint: pass --pid <path> or reload nginx manually: nginx -s reload")
		os.Exit(1)
	}

	pid := strings.TrimSpace(string(data))
	fmt.Printf("Sending reload signal to nginx (pid %s)...\n", pid)
	fmt.Println("Note: actual signal sending requires root. Use: nginx -s reload")
}
