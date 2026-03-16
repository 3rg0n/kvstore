package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ecopelan/kvstore/internal/auth"
	"github.com/ecopelan/kvstore/internal/config"
	"github.com/ecopelan/kvstore/internal/platform"
	"github.com/ecopelan/kvstore/internal/server"
	svc "github.com/ecopelan/kvstore/internal/service"
	"github.com/ecopelan/kvstore/internal/store"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:          "kvstore",
	Short:        "Lightweight encrypted key-value store",
	Long:         "A cross-platform, TPM-ready encrypted key-value store for secrets and configuration management.",
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(initCmd, setCmd, getCmd, deleteCmd, listCmd, serveCmd, serviceCmd, versionCmd, appCmd)

	getCmd.Flags().Bool("json", false, "output in JSON format")
	initCmd.Flags().Bool("tpm", false, "seal master key with TPM/Secure Enclave (auto-detected if omitted)")
	serveCmd.Flags().StringP("addr", "a", config.DefaultAddr, "listen address")
	serveCmd.Flags().Bool("no-auth", false, "disable app token authentication (development/migration only)")

	appRegisterCmd.Flags().String("binary", "", "path to the application binary (required)")
	appRegisterCmd.Flags().StringSlice("namespaces", nil, "allowed namespaces (comma-separated, required)")
	appRegisterCmd.Flags().String("name", "", "friendly name for the app (defaults to binary filename)")
	appRegisterCmd.Flags().String("verify", "auto", "verification mode: hash, signature, or auto")
	_ = appRegisterCmd.MarkFlagRequired("binary")
	_ = appRegisterCmd.MarkFlagRequired("namespaces")

	appUpdateNsCmd.Flags().StringSlice("namespaces", nil, "new allowed namespaces (comma-separated, required)")
	_ = appUpdateNsCmd.MarkFlagRequired("namespaces")
}

// --- helpers ---

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd()) //nolint:gosec // fd fits in int on all supported platforms
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return pw, err
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func getPassword() ([]byte, error) {
	if pw := os.Getenv("KVSTORE_KEY"); pw != "" {
		return []byte(pw), nil
	}
	return readPassword("Enter master password: ")
}

// confirmIdentity verifies human presence using platform biometric if available,
// falling back to master password re-entry.
func confirmIdentity(reason string, s *store.Store) error {
	plat := platform.New()
	if plat.HasBiometric() {
		fmt.Fprintf(os.Stderr, "Biometric verification: %s\n", reason)
		if err := plat.BiometricPrompt(reason); err == nil {
			return nil
		}
		fmt.Fprintln(os.Stderr, "Biometric failed, falling back to password.")
	}

	pw, err := readPassword("Enter master password: ")
	if err != nil {
		return err
	}
	return s.Unlock(pw)
}

func openAndUnlock() (*store.Store, error) {
	if err := config.EnsureDataDir(); err != nil {
		return nil, err
	}

	s, err := store.Open(config.StorePath())
	if err != nil {
		return nil, err
	}

	if !s.IsInitialized() {
		_ = s.Close()
		return nil, store.ErrNotInitialized
	}

	// Auto-detect TPM mode
	if s.IsTPMMode() {
		plat := platform.New()
		if err := s.UnlockTPM(plat); err != nil {
			_ = s.Close()
			return nil, fmt.Errorf("TPM unlock: %w", err)
		}
		return s, nil
	}

	pw, err := getPassword()
	if err != nil {
		_ = s.Close()
		return nil, err
	}

	if err := s.Unlock(pw); err != nil {
		_ = s.Close()
		return nil, err
	}

	return s, nil
}

// --- commands ---

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the encrypted store",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.EnsureDataDir(); err != nil {
			return err
		}

		s, err := store.Open(config.StorePath())
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if s.IsInitialized() {
			return errors.New("store already initialized")
		}

		useTPM, _ := cmd.Flags().GetBool("tpm")
		plat := platform.New()

		// Auto-detect TPM if flag not explicitly set
		if !cmd.Flags().Changed("tpm") && plat.HasTPM() {
			fmt.Fprintln(os.Stderr, "TPM detected. Use --tpm to seal master key with hardware.")
		}

		if useTPM {
			if !plat.HasTPM() {
				return errors.New("TPM not available on this system")
			}
			if err := s.InitTPM(plat); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Store initialized with TPM-sealed key at %s\n", config.StorePath())
			return nil
		}

		pw1, err := readPassword("Enter master password: ")
		if err != nil {
			return err
		}

		pw2, err := readPassword("Confirm master password: ")
		if err != nil {
			return err
		}

		if string(pw1) != string(pw2) {
			return errors.New("passwords do not match")
		}

		if len(pw1) < 8 {
			return errors.New("password must be at least 8 characters")
		}

		if err := s.Init(pw1); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Store initialized at %s\n", config.StorePath())
		return nil
	},
}

var setCmd = &cobra.Command{
	Use:   "set <namespace> <key> <value>",
	Short: "Set a key-value pair",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if err := s.Set(args[0], args[1], []byte(args[2])); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Set %s/%s\n", args[0], args[1])
		return nil
	},
}

var getCmd = &cobra.Command{
	Use:   "get <namespace> <key>",
	Short: "Get a value by namespace and key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		entry, err := s.Get(args[0], args[1])
		if err != nil {
			return err
		}

		jsonOutput, _ := cmd.Flags().GetBool("json")
		if jsonOutput {
			out := map[string]string{
				"namespace":  args[0],
				"key":        args[1],
				"value":      string(entry.Value),
				"created_at": entry.CreatedAt.Format(time.RFC3339),
				"updated_at": entry.UpdatedAt.Format(time.RFC3339),
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}

		fmt.Println(string(entry.Value))
		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <namespace> <key>",
	Short: "Delete a key",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if err := s.Delete(args[0], args[1]); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "Deleted %s/%s\n", args[0], args[1])
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list [namespace]",
	Short: "List namespaces or keys within a namespace",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if len(args) == 0 {
			namespaces, err := s.ListNamespaces()
			if err != nil {
				return err
			}
			for _, ns := range namespaces {
				fmt.Println(ns)
			}
			return nil
		}

		keys, err := s.List(args[0])
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	},
}

// --- serve ---

type serveProgram struct {
	addr   string
	noAuth bool
	srv    *server.Server
	store  *store.Store
	logger *slog.Logger
}

func (p *serveProgram) Start(_ service.Service) error {
	var err error
	p.store, err = openAndUnlock()
	if err != nil {
		return err
	}

	p.logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

	var authMw *auth.Middleware
	var ln net.Listener
	plat := platform.New()

	if !p.noAuth {
		reg := auth.NewRegistry(p.store)
		authMw = auth.NewMiddleware(reg, plat, p.logger)

		sockPath := config.SocketPath()
		ln, err = plat.Listener(sockPath)
		if err != nil {
			p.logger.Warn("platform listener failed, falling back to TCP",
				"err", err, "addr", p.addr)
			ln, err = net.Listen("tcp", p.addr)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}
		}
		p.logger.Info("app token authentication enabled", "listener", ln.Addr())
	} else {
		p.logger.Warn("app token authentication DISABLED (--no-auth)")
		ln, err = net.Listen("tcp", p.addr)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}
	}

	p.srv = server.New(p.store, p.logger, authMw)

	go func() {
		if err := p.srv.Start(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			p.logger.Error("server error", "err", err)
		}
	}()
	return nil
}

func (p *serveProgram) Stop(_ service.Service) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if p.srv != nil {
		err = p.srv.Shutdown(ctx)
	}
	if p.store != nil {
		if cerr := p.store.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr, _ := cmd.Flags().GetString("addr")
		noAuth, _ := cmd.Flags().GetBool("no-auth")

		prg := &serveProgram{addr: addr, noAuth: noAuth}

		svcCfg := &service.Config{
			Name: "kvstore",
		}
		s, err := service.New(prg, svcCfg)
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}

		return s.Run()
	},
}

// --- service management ---

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the system service",
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceStartCmd, serviceStopCmd, serviceStatusCmd)
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install kvstore as a system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		if err := s.Install(); err != nil {
			return err
		}
		fmt.Println("Service installed. Set KVSTORE_KEY env var before starting.")
		return nil
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall the system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		if err := s.Uninstall(); err != nil {
			return err
		}
		fmt.Println("Service uninstalled.")
		return nil
	},
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		if err := s.Start(); err != nil {
			return err
		}
		fmt.Println("Service started.")
		return nil
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		if err := s.Stop(); err != nil {
			return err
		}
		fmt.Println("Service stopped.")
		return nil
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		status, err := s.Status()
		if err != nil {
			return err
		}
		switch status {
		case service.StatusRunning:
			fmt.Println("running")
		case service.StatusStopped:
			fmt.Println("stopped")
		default:
			fmt.Println("unknown")
		}
		return nil
	},
}

// --- app management ---

var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Manage registered applications",
}

func init() {
	appCmd.AddCommand(appRegisterCmd, appListCmd, appRevokeCmd, appRehashCmd, appUpdateNsCmd)
}

var appRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an application for API access",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		binaryPath, _ := cmd.Flags().GetString("binary")
		namespaces, _ := cmd.Flags().GetStringSlice("namespaces")
		name, _ := cmd.Flags().GetString("name")
		verifyStr, _ := cmd.Flags().GetString("verify")

		var mode auth.VerifyMode
		switch verifyStr {
		case "hash":
			mode = auth.VerifyHash
		case "signature":
			mode = auth.VerifySignature
		case "auto":
			mode = auth.VerifyAuto
		default:
			return fmt.Errorf("invalid verify mode %q: must be hash, signature, or auto", verifyStr)
		}

		if err := confirmIdentity("Register application for API access", s); err != nil {
			return fmt.Errorf("identity confirmation failed: %w", err)
		}

		reg := auth.NewRegistry(s)
		token, err := reg.Register(name, binaryPath, namespaces, mode)
		if err != nil {
			return err
		}

		// Show the registered app details
		apps, err := reg.List()
		if err != nil {
			return err
		}
		for _, app := range apps {
			if app.TokenHash == "" {
				continue
			}
			// Find the just-registered app (most recent)
			if app.Name == name || (name == "" && app.BinaryPath != "") {
				fmt.Fprintf(os.Stderr, "Registered app %q (ID: %s)\n", app.Name, app.ID)
				fmt.Fprintf(os.Stderr, "  Binary:     %s\n", app.BinaryPath)
				fmt.Fprintf(os.Stderr, "  Verify:     %s\n", app.VerifyMode)
				if app.VerifyMode == auth.VerifyHash {
					fmt.Fprintf(os.Stderr, "  Hash:       %s\n", app.BinaryHash)
				} else {
					fmt.Fprintf(os.Stderr, "  Signer:     %s\n", app.SignerID)
				}
				fmt.Fprintf(os.Stderr, "  Namespaces: %s\n", strings.Join(app.Namespaces, ", "))
				break
			}
		}

		fmt.Fprintf(os.Stderr, "\nApp token (save this, shown only once):\n")
		fmt.Println(token)
		return nil
	},
}

var appListCmd = &cobra.Command{
	Use:   "list",
	Short: "List registered applications",
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		reg := auth.NewRegistry(s)
		apps, err := reg.List()
		if err != nil {
			return err
		}

		if len(apps) == 0 {
			fmt.Fprintln(os.Stderr, "No registered apps.")
			return nil
		}

		for _, app := range apps {
			fmt.Printf("%-36s  %-20s  %-10s  %s\n",
				app.ID, app.Name, app.VerifyMode, strings.Join(app.Namespaces, ","))
		}
		return nil
	},
}

var appRevokeCmd = &cobra.Command{
	Use:   "revoke <app-id>",
	Short: "Revoke an application's access",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if err := confirmIdentity("Revoke application access", s); err != nil {
			return fmt.Errorf("identity confirmation failed: %w", err)
		}

		reg := auth.NewRegistry(s)
		if err := reg.Revoke(args[0]); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "App %s revoked.\n", args[0])
		return nil
	},
}

var appRehashCmd = &cobra.Command{
	Use:   "rehash <app-id>",
	Short: "Re-hash a binary after update (hash mode only)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		if err := confirmIdentity("Re-hash application binary", s); err != nil {
			return fmt.Errorf("identity confirmation failed: %w", err)
		}

		reg := auth.NewRegistry(s)
		if err := reg.Rehash(args[0]); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "App %s rehashed.\n", args[0])
		return nil
	},
}

var appUpdateNsCmd = &cobra.Command{
	Use:   "update-ns <app-id>",
	Short: "Update namespace ACLs for an application",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := openAndUnlock()
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()

		namespaces, _ := cmd.Flags().GetStringSlice("namespaces")

		if err := confirmIdentity("Update application namespace ACLs", s); err != nil {
			return fmt.Errorf("identity confirmation failed: %w", err)
		}

		reg := auth.NewRegistry(s)
		if err := reg.UpdateNamespaces(args[0], namespaces); err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "App %s namespaces updated to: %s\n", args[0], strings.Join(namespaces, ", "))
		return nil
	},
}

// --- version ---

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("kvstore %s\n", version)
	},
}
