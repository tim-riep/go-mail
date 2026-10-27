package translogtest

import (
	"errors"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

func TestUnverifiedNeedsSwitch(t *testing.T) {
	if l, err := NewUnverified(false); !errors.Is(err, translog.ErrNoLog) || l != nil {
		t.Fatal("without --insecure-no-log there must be no log")
	}
	l, err := NewUnverified(true)
	if err != nil {
		t.Fatal(err)
	}
	var log translog.Log = l
	if log.Verified() {
		t.Fatal("Unverified must report Verified() == false")
	}
	var id store.ID
	for _, err := range []error{
		log.AppendUser(id, nil), log.AppendEpoch(id, 1, nil), log.AppendAddress(nil), log.AppendPlatform("x", nil),
		log.CheckUser(id, nil), log.CheckGeneration(id, 1), log.CheckRevokedSignature(id, 1, nil),
		log.CheckEpoch(id, 1, nil), log.CheckAddress("a@b", id, 0), log.CheckPlatform("x", nil), log.CheckFresh(time.Now()),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if translog.Warning == "" {
		t.Fatal("warning text")
	}
	if i, err := log.Append(translog.KindUser, nil); i != NoIndex || err != nil {
		t.Fatal("Append")
	}
	if h, err := log.Refresh(time.Now()); h != nil || err != nil {
		t.Fatal("Refresh")
	}
	if _, err := log.Head(); !errors.Is(err, translog.ErrNoLog) {
		t.Fatal("Head")
	}
	if _, err := log.Entry(0); !errors.Is(err, translog.ErrNoLog) {
		t.Fatal("Entry")
	}
	if _, err := log.InclusionProof(0, 1); !errors.Is(err, translog.ErrNoLog) {
		t.Fatal("InclusionProof")
	}
	if _, err := log.ConsistencyProof(1, 2); !errors.Is(err, translog.ErrNoLog) {
		t.Fatal("ConsistencyProof")
	}
	if es, err := log.Lookup(translog.KindEpoch, nil); es != nil || err != nil {
		t.Fatal("Lookup")
	}
}
