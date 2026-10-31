package runeimport

import (
	"encoding/json"
	"strings"
	"testing"

	"example.com/yggdrasil-panel/internal/rune"
)

func TestImportEggTranslatesStableValidatedTemplate(t *testing.T) {
	input := `{
  "name":"My Server!!!",
  "author":"Example Author",
  "description":"Imported server",
  "docker_image":"fallback:1",
  "docker_images":{"Zulu":"last:1","Alpha":"selected:2"},
  "startup":"java -jar {{SERVER_JARFILE}}",
  "config":{"files":{"server.properties":{},"config/server.conf":{}},"startup":{"done":["Loading (1/2).","ignored"]}},
  "scripts":{"installation":{"script":"echo install","container":"installer:3","entrypoint":"ignored-entrypoint"}},
  "variables":[
    {"name":"Jar","env_variable":"SERVER_JARFILE","default_value":"server.jar","rules":"required|string"},
    {"name":"Enable","env_variable":"ENABLE_FEATURE","default_value":"false","rules":"boolean"},
    {"name":"Threads","env_variable":"THREADS","default_value":"4","rules":"integer|min:1"},
    {"name":"Mode","env_variable":"MODE","default_value":"safe","rules":"in:safe,fast, debug|required"},
    {"name":"Token","env_variable":"SERVER_TOKEN","default_value":"import-secret-value","rules":"required|string"}
  ]
}`
	gs, warnings, err := ImportEgg([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if gs.ID != "my-server" || gs.Name != "My Server!!!" || gs.Category != "Imported" || gs.Version != 1 || gs.Author != "Example Author" {
		t.Fatalf("unexpected identity: %#v", gs)
	}
	if gs.Docker.Image != "selected:2" || gs.Startup.Command != "java -jar {{SERVER_JARFILE}}" || gs.Startup.DoneRegex != `Loading \(1/2\)\.` {
		t.Fatalf("unexpected image or startup mapping: %#v %#v", gs.Docker, gs.Startup)
	}
	if gs.Install == nil || gs.Install.Image != "installer:3" || gs.Install.Script != "echo install" {
		t.Fatalf("egg install script was not mapped: %#v", gs.Install)
	}
	if len(gs.ConfigFiles) != 2 || gs.ConfigFiles[0] != "config/server.conf" || gs.ConfigFiles[1] != "server.properties" {
		t.Fatalf("egg config-file keys were not sorted: %#v", gs.ConfigFiles)
	}
	if len(gs.Variables) != 5 || gs.Variables[0].Type != "string" || gs.Variables[1].Type != "bool" || gs.Variables[2].Type != "int" || gs.Variables[3].Type != "select" || len(gs.Variables[3].Options) != 3 || !gs.Variables[3].Required {
		t.Fatalf("egg validation rules were not translated: %#v", gs.Variables)
	}
	if !gs.Variables[4].Secret || gs.Variables[4].Default != nil || len(warnings) != 1 {
		t.Fatalf("secret egg default was not discarded and reported: variable=%#v warnings=%#v", gs.Variables[4], warnings)
	}
	encoded, err := json.Marshal(gs)
	if err != nil || strings.Contains(string(encoded), "import-secret-value") {
		t.Fatalf("imported secret was retained: err=%v body=%s", err, encoded)
	}
	if err = gs.Validate(); err != nil {
		t.Fatalf("generated egg template did not validate: %v", err)
	}
}

func TestImportEggRejectsMissingIdentityImageAndSizeOverflow(t *testing.T) {
	for name, input := range map[string]string{
		"empty name":    `{"name":"💡","docker_image":"app:1","startup":"run"}`,
		"missing image": `{"name":"Example","startup":"run"}`,
		"invalid JSON":  `{"name":`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ImportEgg([]byte(input)); err == nil {
				t.Fatal("invalid egg was accepted")
			}
		})
	}
	if _, _, err := ImportEgg([]byte(strings.Repeat("x", MaxSize+1))); err == nil {
		t.Fatal("oversized egg was accepted")
	}
}

func TestImportXMLMapsDocumentedFieldsAndDefaults(t *testing.T) {
	input := `<gameskill>
  <id>xml-app</id><name>XML App</name><category>Tools</category><description>XML import</description><author>XML Author</author><version>0</version><icon>icon.svg</icon>
  <docker><image>example/xml:1</image></docker>
  <variables><variable><key>MODE</key><name>Mode</name><type>select</type><options><option>safe</option><option>fast</option></options><default>safe</default><required>true</required></variable><variable><key>ACCESS_TOKEN</key><type>string</type><default>xml-secret-value</default></variable></variables>
  <install><image>installer:2</image><script>echo setup</script></install>
  <startup><command>exec app --mode {{MODE}}</command><done_regex>started</done_regex><stop>stop</stop></startup>
  <config_files><file>app.conf</file><file>config/main.properties</file></config_files>
  <ports><port><name>web</name><default>8080</default></port><port><name>query</name><default>27015</default><protocol>udp</protocol></port></ports>
  <unsupported><unsafe>ignored</unsafe></unsupported>
</gameskill>`
	gs, warnings, err := ImportXML([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if gs.ID != "xml-app" || gs.Category != "Tools" || gs.Version != 1 || gs.Author != "XML Author" || gs.Icon != "icon.svg" {
		t.Fatalf("unexpected XML metadata: %#v", gs)
	}
	if gs.Install == nil || gs.Install.Image != "installer:2" || gs.Startup.Command != "exec app --mode {{MODE}}" || gs.Startup.Stop != "stop" {
		t.Fatalf("XML install or startup fields were not mapped: install=%#v startup=%#v", gs.Install, gs.Startup)
	}
	if len(gs.ConfigFiles) != 2 || len(gs.Ports) != 2 || gs.Ports[0].Protocol != "tcp" || gs.Ports[1].Protocol != "udp" {
		t.Fatalf("XML config files or ports were not mapped: files=%#v ports=%#v", gs.ConfigFiles, gs.Ports)
	}
	if !gs.Variables[1].Secret || gs.Variables[1].Default != nil || len(warnings) != 1 {
		t.Fatalf("XML secret default was not discarded: %#v warnings=%#v", gs.Variables[1], warnings)
	}
	if err = gs.Validate(); err != nil {
		t.Fatalf("generated XML template did not validate: %v", err)
	}
	if _, _, err = ImportXML([]byte(`<other><name>wrong root</name></other>`)); err == nil {
		t.Fatal("non-gameskill XML root was accepted")
	}
	if _, _, err = ImportXML([]byte(strings.Repeat("x", MaxSize+1))); err == nil {
		t.Fatal("oversized XML was accepted")
	}
	if !rune.SensitiveVariableName("DATABASE_URL") {
		t.Fatal("database URL did not use shared secret-name detection")
	}
}
