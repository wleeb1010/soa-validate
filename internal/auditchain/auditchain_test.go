package auditchain

import "testing"

func TestVerifyChain_Empty(t *testing.T) {
	if idx, err := VerifyChain(nil); err != nil || idx != -1 {
		t.Errorf("empty chain: idx=%d err=%v; want -1,nil", idx, err)
	}
}

func TestVerifyChain_Valid(t *testing.T) {
	rs := []Record{
		{PrevHash: "GENESIS", ThisHash: "h1"},
		{PrevHash: "h1", ThisHash: "h2"},
		{PrevHash: "h2", ThisHash: "h3"},
	}
	if idx, err := VerifyChain(rs); err != nil || idx != -1 {
		t.Errorf("valid chain: idx=%d err=%v; want -1,nil", idx, err)
	}
}

func TestVerifyChain_FirstNotGenesis(t *testing.T) {
	rs := []Record{{PrevHash: "nope", ThisHash: "h1"}}
	if idx, err := VerifyChain(rs); idx != 0 || err == nil {
		t.Errorf("bad first: idx=%d err=%v; want 0,err", idx, err)
	}
}

func TestVerifyChain_MidChainBreak(t *testing.T) {
	rs := []Record{
		{PrevHash: "GENESIS", ThisHash: "h1"},
		{PrevHash: "h1", ThisHash: "h2"},
		{PrevHash: "WRONG", ThisHash: "h3"},
		{PrevHash: "h3", ThisHash: "h4"},
	}
	idx, err := VerifyChain(rs)
	if idx != 2 || err == nil {
		t.Errorf("mid break: idx=%d err=%v; want 2,err", idx, err)
	}
}

func TestTamper_BreaksChainAtIndex(t *testing.T) {
	rs := []Record{
		{PrevHash: "GENESIS", ThisHash: "h1"},
		{PrevHash: "h1", ThisHash: "h2"},
		{PrevHash: "h2", ThisHash: "h3"},
	}
	tampered := Tamper(rs, 2)
	if idx, err := VerifyChain(tampered); idx != 2 || err == nil {
		t.Errorf("tamper at 2: got idx=%d err=%v; want 2,err", idx, err)
	}
	// Original must be untouched.
	if rs[2].PrevHash != "h2" {
		t.Error("Tamper mutated the source slice")
	}
}
