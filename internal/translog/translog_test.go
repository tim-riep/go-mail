package translog

import (
	"errors"
	"testing"
	"time"

	"github.com/tim-riep/go-mail/internal/store"
)

func TestUnverifiedNeedsSwitch(t *testing.T) {
	if l, err := NewUnverified(false); !errors.Is(err, ErrNoLog) || l != nil {
		t.Fatal("without --insecure-no-log there must be no log")
	}
	l, err := NewUnverified(true)
	if err != nil {
		t.Fatal(err)
	}
	var log Log = l
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
	if Warning == "" {
		t.Fatal("warning text")
	}
}
