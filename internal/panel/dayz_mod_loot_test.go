package panel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dayzTestTypes = `<types><type name="Rifle"><nominal>2</nominal><lifetime>60</lifetime></type></types>`

func TestNormalizeDayZModTypesDocumentAndFragment(t *testing.T) {
	rooted := []byte(`<?xml version="1.0"?><types><type name="Rifle"><lifetime>60</lifetime></type></types>`)
	got, parsed, fragment, err := normalizeDayZModTypes(rooted)
	if err != nil {
		t.Fatalf("normalize rooted types file: %v", err)
	}
	if fragment || parsed.count != 1 || len(parsed.lifetimes) != 1 || string(got) != string(rooted) {
		t.Fatalf("rooted file changed or parsed incorrectly: fragment=%t types=%d lifetimes=%d", fragment, parsed.count, len(parsed.lifetimes))
	}

	loose := []byte("<?xml version=\"1.0\"?>\n<type name=\"Rifle\"><lifetime>60</lifetime></type>\n<type name=\"Bandage\"><lifetime>120</lifetime></type>")
	got, parsed, fragment, err = normalizeDayZModTypes(loose)
	if err != nil {
		t.Fatalf("normalize loose type fragment: %v", err)
	}
	if !fragment || parsed.count != 2 || len(parsed.lifetimes) != 2 || !strings.HasPrefix(string(got), "<types>\n") || !strings.HasSuffix(string(got), "\n</types>\n") {
		t.Fatalf("fragment was not wrapped with both types retained: fragment=%t types=%d lifetimes=%d output=%s", fragment, parsed.count, len(parsed.lifetimes), got)
	}
}

func TestNormalizeDayZModTypesRejectsInvalidDocuments(t *testing.T) {
	for name, input := range map[string]string{
		"wrong root":       `<globals><type name="Rifle"><lifetime>60</lifetime></type></globals>`,
		"nonnumeric life":  `<types><type name="Rifle"><lifetime>long</lifetime></type></types>`,
		"nested type":      `<types><type name="Outer"><type name="Inner"><lifetime>60</lifetime></type></type></types>`,
		"doctype":          `<!DOCTYPE types [<!ENTITY x "no">]><types><type name="Rifle"><lifetime>60</lifetime></type></types>`,
		"missing lifetime": `<types><type name="Rifle" /></types>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := normalizeDayZModTypes([]byte(input)); err == nil {
				t.Fatalf("accepted invalid mod loot XML: %s", input)
			}
		})
	}
}

func TestScanDayZModLootIsBoundToInstalledModFolders(t *testing.T) {
	root := t.TempDir()
	missionRoot := filepath.Join(t.TempDir(), "mission")
	if err := os.MkdirAll(missionRoot, 0750); err != nil {
		t.Fatal(err)
	}
	modRoot := filepath.Join(root, "@123")
	writeDayZTestFile(t, filepath.Join(modRoot, "meta.cpp"), `name = "Expansion Test";`)
	writeDayZTestFile(t, filepath.Join(modRoot, "types.xml"), dayzTestTypes)
	fragmentPath := filepath.Join(modRoot, "Addons", "fragment.xml")
	writeDayZTestFile(t, fragmentPath, `<type name="FieldRation"><lifetime>90</lifetime></type>`)
	writeDayZTestFile(t, filepath.Join(modRoot, "storage_1", "hidden.xml"), dayzTestTypes)
	if err := os.Symlink(filepath.Join(modRoot, "types.xml"), filepath.Join(modRoot, "linked.xml")); err != nil {
		t.Fatalf("create symlink fixture: %v", err)
	}
	writeDayZTestFile(t, filepath.Join(root, "ordinary-folder", "types.xml"), dayzTestTypes)
	conflictTarget := filepath.Join(missionRoot, "Expansion_Test", "Addons", "fragment.xml")
	writeDayZTestFile(t, conflictTarget, "operator-owned file")

	imports := []dayzModTypesImport{{SourcePath: "@123/types.xml", TargetPath: "Expansion_Test/types.xml", ModName: "Expansion_Test"}}
	summary, err := scanDayZModLoot(root, missionRoot, imports)
	if err != nil {
		t.Fatalf("scan mod folders: %v", err)
	}
	if summary.Truncated || len(summary.Candidates) != 2 {
		t.Fatalf("expected 2 valid mod loot files and a complete scan, got candidates=%d truncated=%t", len(summary.Candidates), summary.Truncated)
	}
	bySource := map[string]dayzModLootCandidate{}
	for _, candidate := range summary.Candidates {
		bySource[candidate.SourcePath] = candidate
	}
	rootFile, ok := bySource["@123/types.xml"]
	if !ok || rootFile.DisplayName != "Expansion Test" || rootFile.ModName != "Expansion_Test" || !rootFile.Expansion || !rootFile.Imported || rootFile.TargetPath != "Expansion_Test/types.xml" {
		t.Fatalf("metadata/import badges were not derived as expected: %#v", rootFile)
	}
	fragment, ok := bySource["@123/Addons/fragment.xml"]
	if !ok || !fragment.Fragment || !fragment.Expansion || !fragment.TargetExists || fragment.TargetPath != "Expansion_Test/Addons/fragment.xml" {
		t.Fatalf("fragment or mission-target conflict was not detected: %#v", fragment)
	}
	if _, ok = bySource["@123/storage_1/hidden.xml"]; ok {
		t.Fatal("storage XML was included in mod loot scan")
	}
	if _, ok = bySource["@123/linked.xml"]; ok {
		t.Fatal("symlinked XML was included in mod loot scan")
	}
	if _, ok = bySource["ordinary-folder/types.xml"]; ok {
		t.Fatal("XML outside a top-level @mod folder was included")
	}
}

func TestDayZEconomyRecreatesMissingImportedFileAndRegistration(t *testing.T) {
	a, d, _ := testApp(t)
	dataDir := t.TempDir()
	if _, err := d.Exec(`INSERT INTO servers(id,name,gameskill_id,status,installed,env_json,ports_json,data_dir) VALUES('dayz-test','DayZ test','dayz','stopped',1,'{}','{}',?)`, dataDir); err != nil {
		t.Fatal(err)
	}
	const target = "Expansion/addons/types.xml"
	const source = "@123/addons/types.xml"
	writeDayZTestFile(t, filepath.Join(dataDir, filepath.FromSlash(source)), `<type name="Rifle"><lifetime>60</lifetime></type>`)
	missionRoot := filepath.Join(dataDir, "mpmissions", "dayzOffline.chernarusplus")
	writeDayZTestFile(t, filepath.Join(missionRoot, "cfgeconomycore.xml"), `<economycore><classes/><defaults/></economycore>`)
	if err := os.MkdirAll(filepath.Join(missionRoot, "db"), 0750); err != nil {
		t.Fatal(err)
	}
	state := dayzEconomyState{
		MinLifetimeHours: 1,
		Globals:          map[string]int{},
		RegisteredFiles:  []string{target},
		ModImports:       []dayzModTypesImport{{SourcePath: source, TargetPath: target, ModName: "Expansion"}},
	}
	if err := a.saveDayZEconomyState(context.Background(), "dayz-test", state); err != nil {
		t.Fatal(err)
	}
	server := Server{ID: "dayz-test", Name: "DayZ test", GameskillID: "dayz", DataDir: dataDir, Env: map[string]string{}, Ports: map[string]int{}}
	if err := a.applyDayZEconomySettings(server); err != nil {
		t.Fatalf("restore imported file and Economy settings: %v", err)
	}
	targetFull := filepath.Join(missionRoot, filepath.FromSlash(target))
	data, err := os.ReadFile(targetFull)
	if err != nil {
		t.Fatalf("imported target was not restored: %v", err)
	}
	if !strings.Contains(string(data), "<types>") || !strings.Contains(string(data), "<lifetime>3600</lifetime>") {
		t.Fatalf("fragment was not wrapped and lifetime floor was not applied: %s", data)
	}
	corePath, err := os.ReadFile(filepath.Join(missionRoot, "cfgeconomycore.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(corePath), `<ce folder="Expansion/addons">`) || !strings.Contains(string(corePath), `<file name="types.xml" type="types" />`) {
		t.Fatalf("saved imported file was not registered in Economy core: %s", corePath)
	}

	// A later template update may leave an existing destination intact but lose
	// its registration; reapply must restore that registration without replacing
	// the mission file the operator already changed.
	writeDayZTestFile(t, targetFull, `<types><type name="Rifle"><lifetime>7200</lifetime></type></types>`)
	writeDayZTestFile(t, filepath.Join(missionRoot, "cfgeconomycore.xml"), `<economycore><classes/><defaults/></economycore>`)
	if err = a.applyDayZEconomySettings(server); err != nil {
		t.Fatalf("re-register existing imported file: %v", err)
	}
	data, err = os.ReadFile(targetFull)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "<lifetime>7200</lifetime>") {
		t.Fatalf("existing imported target was overwritten during reapply: %s", data)
	}
}

func TestCleanDayZModSourcePathRejectsPathsOutsideModFolders(t *testing.T) {
	for _, input := range []string{"../outside/types.xml", "mod/types.xml", "@123/storage_1/types.xml", "/@123/types.xml", "@123/../../etc/passwd.xml"} {
		if _, err := cleanDayZModSourcePath(input); err == nil {
			t.Errorf("accepted unsafe mod source path %q", input)
		}
	}
	if got, err := cleanDayZModSourcePath(`@123\Addons\types.xml`); err != nil || got != "@123/Addons/types.xml" {
		t.Fatalf("normalized valid source path incorrectly: %q, %v", got, err)
	}
}

func writeDayZTestFile(t *testing.T, full, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(full), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}
