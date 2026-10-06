package skills

import "testing"

func TestResolveSkillNameReusesEmbeddedIndex(t *testing.T) {
	query := "graphql batching"
	first, firstOK := ResolveSkillName(query)

	skillIndexMu.Lock()
	initialEntries := len(skillIndexCache)
	skillIndexMu.Unlock()

	for range 25 {
		got, ok := ResolveSkillName(query)
		if got != first || ok != firstOK {
			t.Fatalf("resolution changed: (%q, %v) versus (%q, %v)", got, ok, first, firstOK)
		}
	}

	skillIndexMu.Lock()
	finalEntries := len(skillIndexCache)
	skillIndexMu.Unlock()
	if finalEntries != initialEntries {
		t.Fatalf("repeated embedded lookups added %d cached indexes", finalEntries-initialEntries)
	}
}
