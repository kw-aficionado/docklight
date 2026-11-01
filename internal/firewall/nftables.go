package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
)

const (
	nftFamily = "inet"
	nftTable  = "yggdrasil"
	managedBy = "Managed by Docklight"
)

// Available checks the nft binary and read-only netlink access. It does not
// create or change firewall state.
func Available(ctx context.Context) (bool, string) {
	if _, err := exec.LookPath("nft"); err != nil {
		return false, "nftables command is not installed"
	}
	if _, err := run(ctx, "-j", "list", "tables"); err != nil {
		return false, actionableError(err).Error()
	}
	return true, "nftables can be inspected; changes still require CAP_NET_ADMIN"
}

// Reconcile replaces only the Docklight-owned input chain rules and sets.
// Other nftables tables are never touched. The chain and both sets must carry
// Docklight's ownership comment before an existing table is modified.
func Reconcile(ctx context.Context, addresses []netip.Addr) error {
	v4, v6, err := splitAddresses(addresses)
	if err != nil {
		return err
	}
	_, err = run(ctx, "-j", "list", "table", nftFamily, nftTable)
	if err != nil {
		if !tableMissing(err) {
			return actionableError(err)
		}
		if len(v4)+len(v6) == 0 {
			return nil
		}
		return runScript(ctx, initialScript(v4, v6))
	}
	if err = verifyOwnedTable(ctx); err != nil {
		return err
	}
	return runScript(ctx, reconcileScript(v4, v6))
}

func splitAddresses(addresses []netip.Addr) ([]netip.Addr, []netip.Addr, error) {
	v4, v6 := make([]netip.Addr, 0), make([]netip.Addr, 0)
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() {
			return nil, nil, errors.New("invalid IP address in Docklight firewall state")
		}
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		if address.Is4() {
			v4 = append(v4, address)
		} else {
			v6 = append(v6, address)
		}
	}
	sort.Slice(v4, func(i, j int) bool { return v4[i].Less(v4[j]) })
	sort.Slice(v6, func(i, j int) bool { return v6[i].Less(v6[j]) })
	return v4, v6, nil
}

func initialScript(v4, v6 []netip.Addr) string {
	var b strings.Builder
	b.WriteString("add table inet yggdrasil\n")
	b.WriteString("add set inet yggdrasil blocklist4 { type ipv4_addr; flags interval; comment \"Managed by Docklight\"; }\n")
	b.WriteString("add set inet yggdrasil blocklist6 { type ipv6_addr; flags interval; comment \"Managed by Docklight\"; }\n")
	b.WriteString("add chain inet yggdrasil block_input { type filter hook input priority -10; policy accept; comment \"Managed by Docklight\"; }\n")
	b.WriteString("add rule inet yggdrasil block_input ip saddr @blocklist4 tcp dport { 80, 443 } counter drop\n")
	b.WriteString("add rule inet yggdrasil block_input ip6 saddr @blocklist6 tcp dport { 80, 443 } counter drop\n")
	appendElements(&b, v4, v6)
	return b.String()
}

func reconcileScript(v4, v6 []netip.Addr) string {
	var b strings.Builder
	b.WriteString("flush chain inet yggdrasil block_input\n")
	b.WriteString("flush set inet yggdrasil blocklist4\n")
	b.WriteString("flush set inet yggdrasil blocklist6\n")
	b.WriteString("add rule inet yggdrasil block_input ip saddr @blocklist4 tcp dport { 80, 443 } counter drop\n")
	b.WriteString("add rule inet yggdrasil block_input ip6 saddr @blocklist6 tcp dport { 80, 443 } counter drop\n")
	appendElements(&b, v4, v6)
	return b.String()
}

func appendElements(b *strings.Builder, v4, v6 []netip.Addr) {
	for _, address := range v4 {
		fmt.Fprintf(b, "add element inet yggdrasil blocklist4 { %s }\n", address.String())
	}
	for _, address := range v6 {
		fmt.Fprintf(b, "add element inet yggdrasil blocklist6 { %s }\n", address.String())
	}
}

func verifyOwnedTable(ctx context.Context) error {
	checks := []struct {
		args []string
		kind string
		name string
	}{
		{[]string{"-j", "list", "chain", nftFamily, nftTable, "block_input"}, "chain", "block_input"},
		{[]string{"-j", "list", "set", nftFamily, nftTable, "blocklist4"}, "set", "blocklist4"},
		{[]string{"-j", "list", "set", nftFamily, nftTable, "blocklist6"}, "set", "blocklist6"},
	}
	for _, check := range checks {
		data, err := run(ctx, check.args...)
		if err != nil {
			return fmt.Errorf("nftables table inet yggdrasil exists but is missing its Docklight-managed %s %s; inspect it before enabling host IP blocks: %w", check.kind, check.name, actionableError(err))
		}
		if !hasManagedComment(data, check.kind, check.name) {
			return fmt.Errorf("nftables %s inet yggdrasil %s is not marked as Docklight-owned; refusing to modify it", check.kind, check.name)
		}
	}
	return nil
}

func hasManagedComment(data []byte, kind, name string) bool {
	var document struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(data, &document) != nil {
		return false
	}
	for _, entry := range document.Nftables {
		raw, ok := entry[kind]
		if !ok {
			continue
		}
		var object struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Name    string `json:"name"`
			Comment string `json:"comment"`
		}
		if json.Unmarshal(raw, &object) == nil && object.Family == nftFamily && object.Table == nftTable && object.Name == name && object.Comment == managedBy {
			return true
		}
	}
	return false
}

func tableMissing(err error) bool {
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "no such file or directory") || strings.Contains(lower, "no such table") || strings.Contains(lower, "does not exist")
}

func runScript(ctx context.Context, script string) error {
	path, err := exec.LookPath("nft")
	if err != nil {
		return errors.New("nftables command is not installed")
	}
	command := exec.CommandContext(ctx, path, "-f", "-")
	command.Stdin = bytes.NewBufferString(script)
	output, err := command.CombinedOutput()
	if err != nil {
		return actionableError(fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err))
	}
	return nil
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		return nil, errors.New("nftables command is not installed")
	}
	command := exec.CommandContext(ctx, path, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return output, nil
}

func actionableError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "permission denied") {
		return errors.New("host nftables access is denied; grant CAP_NET_ADMIN to the Docklight service (for systemd, add AmbientCapabilities=CAP_NET_ADMIN) or use Cloudflare IP Access Rules")
	}
	if strings.Contains(lower, "nftables command is not installed") || strings.Contains(lower, "executable file not found") {
		return errors.New("nftables is unavailable; install the nftables package or configure Cloudflare IP Access Rules")
	}
	return fmt.Errorf("nftables could not update the Docklight-managed IP rules: %w", err)
}
