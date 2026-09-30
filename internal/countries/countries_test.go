package countries

import "testing"

func TestName(t *testing.T) {
	for code, want := range map[string]string{"us": "США", "GB": "Великобритания", "xx": "XX", "": ""} {
		if got := Name(code); got != want {
			t.Errorf("Name(%q) = %q, want %q", code, got, want)
		}
	}
}
