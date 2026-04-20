package digest

import "testing"

func TestSHA256HexEmpty(t *testing.T) {
	got := SHA256Hex(nil)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("sha256(\"\") = %s, want %s", got, want)
	}
}

func TestSHA256HexAbc(t *testing.T) {
	got := SHA256Hex([]byte("abc"))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("sha256(\"abc\") = %s, want %s", got, want)
	}
}
