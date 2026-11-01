package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"example.com/yggdrasil-panel/internal/config"
	"example.com/yggdrasil-panel/internal/db"
	"example.com/yggdrasil-panel/internal/docker"
	"example.com/yggdrasil-panel/internal/panel"
	"example.com/yggdrasil-panel/internal/security"
)

var version = "dev"
var repository = ""

const defaultConfig = "/etc/yggdrasil/config.yaml"

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run(args []string) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "version", "--version", "-v":
		fmt.Printf("yggdrasil %s\n", version)
		return nil
	case "release-repo":
		fmt.Println(repository)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	case "gen-config":
		path := defaultConfig
		if len(args) > 0 {
			path = args[0]
		}
		c, e := config.Generate(path)
		if e != nil {
			return e
		}
		fmt.Printf("Created config: %s\nAdmin login: %s / %s\nKeep this password safe. It is removed from the config after the first successful start.\n", path, c.Admin.Username, c.Admin.Password)
		return nil
	case "reset-password":
		return resetPassword(args)
	case "reset-2fa":
		return reset2FA(args)
	case "serve":
		return serve(args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}
func usage() {
	fmt.Print(`Docklight game and app server panel

Usage:
  yggdrasil [--config PATH] [serve]
  yggdrasil version
  yggdrasil release-repo
  yggdrasil gen-config [PATH]
  yggdrasil reset-password USER [--config PATH] [--password VALUE]
  yggdrasil reset-2fa USER [--config PATH]
`)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfig, "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path, err := filepath.Abs(*cfgPath)
	if err != nil {
		return err
	}
	newConfig := false
	c, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		c, err = config.Generate(path)
		if err == nil {
			newConfig = true
			fmt.Printf("Created configuration at %s\n", path)
		}
	}
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err = config.EnsureSecret(path, &c); err != nil {
		return err
	}
	d, err := db.Open(c.Database.Path)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer d.Close()
	generated, err := panel.EnsureAdmin(d, c.Admin.Username, c.Admin.Password)
	if err != nil {
		return fmt.Errorf("create initial administrator: %w", err)
	}
	if newConfig && c.Admin.Password != "" {
		fmt.Printf("Initial administrator: %s / %s\n", c.Admin.Username, c.Admin.Password)
	} else if generated != "" {
		fmt.Printf("Initial administrator: %s / %s\n", c.Admin.Username, generated)
	}
	if c.Admin.Password != "" {
		c.Admin.Password = ""
		if err = config.Save(path, c); err != nil {
			return fmt.Errorf("remove bootstrap password from config: %w", err)
		}
	}
	if err = panel.UpsertBuiltins(d); err != nil {
		return fmt.Errorf("seed built-in templates: %w", err)
	}
	engine := docker.New(c.Docker.Socket, c.Docker.APIVersion)
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = engine.Ping(pingCtx)
	cancel()
	if err != nil {
		log.Printf("Docker Engine not ready yet: %v", err)
	}
	app := panel.New(c, path, d)
	app.SetBuildVersion(version)
	app.SetReleaseRepository(repository)
	workerCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	app.StartScheduleWorker(workerCtx)
	app.StartRuntimeMonitor(workerCtx)
	app.StartCloudflareReconciler(workerCtx)
	app.StartNPMReconciler(workerCtx)
	app.StartIPBlockingReconciler(workerCtx)
	app.StartDiskMonitor(workerCtx)
	app.StartWatchdogMonitor(workerCtx)
	app.StartBeaconWorker(workerCtx)
	app.StartPanelUpdateWorker(workerCtx)
	app.StartViolationMonitor(workerCtx)
	addr := fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
	srv := &http.Server{Addr: addr, Handler: app.Router(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	errs := make(chan error, 1)
	go func() { log.Printf("Docklight listening on http://%s", addr); errs <- srv.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signals:
		log.Printf("received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func resetPassword(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("reset-password is a break-glass command; run it as root")
	}
	if len(args) == 0 {
		return errors.New("usage: yggdrasil reset-password USER [--config PATH] [--password VALUE]")
	}
	username := args[0]
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfig, "config path")
	password := fs.String("password", "", "new password; generated if omitted")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	pw := *password
	if pw == "" {
		var err error
		pw, err = config.Password()
		if err != nil {
			return err
		}
	}
	hash, err := security.HashPassword(pw)
	if err != nil {
		return err
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	d, err := db.Open(c.Database.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE users SET password_hash=?,token_version=token_version+1 WHERE username=?`, hash, username)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	if _, err = tx.Exec(`DELETE FROM password_reset_tokens WHERE user_id=(SELECT id FROM users WHERE username=?)`, username); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("Password reset for %s. New password: %s\n", username, pw)
	return nil
}
func reset2FA(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("reset-2fa is a break-glass command; run it as root")
	}
	if len(args) == 0 {
		return errors.New("usage: yggdrasil reset-2fa USER [--config PATH]")
	}
	username := args[0]
	fs := flag.NewFlagSet("reset-2fa", flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfig, "config path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	d, err := db.Open(c.Database.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	res, err := d.Exec(`UPDATE users SET totp_secret='',totp_enabled=0,totp_last_counter=-1,token_version=token_version+1 WHERE username=?`, username)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user %q not found", username)
	}
	fmt.Printf("Two-factor authentication reset for %s. Sign in with the password and enroll again.\n", username)
	return nil
}
