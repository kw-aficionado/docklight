package panel

import (
	"reflect"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
)

func TestStartupSignalReadyUsesConfiguredSignal(t *testing.T) {
	tests := []struct {
		name          string
		gameskill     rune.Rune
		logMatches    bool
		queryResponds bool
		want          bool
	}{
		{name: "no signal configured", want: true},
		{name: "query template waits for a response", gameskill: rune.Rune{Query: &rune.Query{Type: "a2s"}}, want: false},
		{name: "query template is ready after response", gameskill: rune.Rune{Query: &rune.Query{Type: "a2s"}}, queryResponds: true, want: true},
		{name: "log pattern takes precedence", gameskill: rune.Rune{Startup: rune.Startup{DoneRegex: "ready"}, Query: &rune.Query{Type: "a2s"}}, queryResponds: true, want: false},
		{name: "matching log pattern is ready", gameskill: rune.Rune{Startup: rune.Startup{DoneRegex: "ready"}, Query: &rune.Query{Type: "a2s"}}, logMatches: true, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := startupSignalReady(test.gameskill, test.logMatches, test.queryResponds); got != test.want {
				t.Fatalf("startupSignalReady()=%t, want %t", got, test.want)
			}
		})
	}
}

func TestServerStartupCommandOverridesImageEntrypointWhenRequested(t *testing.T) {
	tests := []struct {
		name      string
		gameskill rune.Rune
		wantEntry []string
		wantCmd   []string
	}{
		{
			name:      "shell command replaces the image entrypoint",
			gameskill: rune.Rune{Startup: rune.Startup{Command: "exec ./DayZServer -port={{GAME_PORT}}"}},
			wantEntry: []string{"/bin/sh", "-c"},
			wantCmd:   []string{"exec ./DayZServer -port=2302"},
		},
		{
			name:      "exec command replaces the image entrypoint",
			gameskill: rune.Rune{Startup: rune.Startup{Exec: []string{"./DayZServer", "-config=serverDZ.cfg"}}},
			wantEntry: []string{"./DayZServer"},
			wantCmd:   []string{"-config=serverDZ.cfg"},
		},
		{
			name:      "keep entrypoint passes configured arguments through",
			gameskill: rune.Rune{Docker: rune.Docker{KeepEntrypoint: true}, Startup: rune.Startup{Exec: []string{"serve", "--port={{GAME_PORT}}"}}},
			wantCmd:   []string{"serve", "--port=2302"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entrypoint, command := serverStartupCommand(test.gameskill, map[string]string{"GAME_PORT": "2302"})
			if !reflect.DeepEqual(entrypoint, test.wantEntry) || !reflect.DeepEqual(command, test.wantCmd) {
				t.Fatalf("serverStartupCommand() = (%q, %q), want (%q, %q)", entrypoint, command, test.wantEntry, test.wantCmd)
			}
		})
	}
}
