package client

import (
	"errors"

	"github.com/tim-riep/go-mail/internal/envelope"
	"github.com/tim-riep/go-mail/internal/keys"
	"github.com/tim-riep/go-mail/internal/store"
	"github.com/tim-riep/go-mail/internal/translog"
)

// causeUnreadable is the fixed cause for a file that cannot be read: not
// a regular file (store.ErrNotRegular, warnCause), or for a mail file of
// an entry marked unprocessed an error of the system on its open, stat or
// read (unreadableCause).
const causeUnreadable = "Datei nicht lesbar"

// warnCause returns a fixed description of err for a warning. A warning
// names IDs, numbers and this cause only, never the text of an error: it
// may name files of the data directory or carry text of other parties
// (task 06g). The error itself is still returned to the caller.
func warnCause(err error) string {
	switch {
	case err == nil:
		return "ohne Angabe"
	case errors.Is(err, errResign):
		return "die neue Datei, die Postfachsperre oder der lokale Zustand konnte nicht geschrieben werden"
	case errors.Is(err, errChanged):
		return "die Datei wurde zwischen Lesen und Sperren ersetzt oder entfernt"
	case errors.Is(err, errOwnGen):
		return "die aktuelle Generation dieses Benutzers ist durch user.rec und das Transparenzlog nicht bestätigt"
	case errors.Is(err, errVersionLimit):
		return "die Versionsnummer der Metadaten ist erschöpft"
	case errors.Is(err, errSegmentLimit):
		return "mehr Indexsegmente in der Epoche, als ein Lauf liest"
	case errors.Is(err, errNotChecked):
		return "von einer widerrufenen Generation signiert und vorher nicht geprüft"
	case errors.Is(err, ErrPlatformRevoked), errors.Is(err, translog.ErrRevoked):
		return "Generation widerrufen"
	case errors.Is(err, ErrRevoked):
		return "von einer widerrufenen Generation signiert und nicht gegengezeichnet"
	case errors.Is(err, ErrDiscardedEpoch):
		return "die Epoche ist verworfen"
	case errors.Is(err, ErrStaleEpoch):
		return "für eine Epoche nach dem Beginn einer neueren verschlüsselt"
	case errors.Is(err, ErrEpoch):
		return "die Epoche liegt außerhalb der geprüften Kette"
	case errors.Is(err, ErrReplay):
		return "ältere Version als bereits gesehen"
	case errors.Is(err, ErrMailHash):
		return "die Mail passt nicht zu ihren Metadaten"
	case errors.Is(err, errHeader):
		return "Kopf der Mail nicht auswertbar"
	case errors.Is(err, ErrMismatch):
		return "die Datei passt nicht zu ihrem Ort oder ihren Metadaten"
	case errors.Is(err, ErrPlatform):
		return "Plattformzertifikat oder Annahmeschlüssel nicht gültig"
	case errors.Is(err, ErrSigner), errors.Is(err, envelope.ErrSigner), errors.Is(err, envelope.ErrSignature),
		errors.Is(err, envelope.ErrUnsigned), errors.Is(err, keys.ErrSignature):
		return "Signatur ungültig oder Unterzeichner nicht zugelassen"
	case errors.Is(err, ErrWrap):
		return "Epochenschlüssel nicht verfügbar"
	case errors.Is(err, envelope.ErrNoRecipient), errors.Is(err, envelope.ErrUnwrap), errors.Is(err, envelope.ErrDecrypt):
		return "Entschlüsselung fehlgeschlagen"
	case errors.Is(err, envelope.ErrSuite):
		return "Algorithmensatz passt nicht"
	case errors.Is(err, ErrAddressSuperseded):
		return "Zuordnung einer abgelösten Admin-Generation"
	case errors.Is(err, ErrAddress):
		return "Adresse nicht zugeordnet"
	case errors.Is(err, ErrSuperseded):
		return "user.rec ist veraltet"
	case errors.Is(err, ErrLog), errors.Is(err, translog.ErrStale), errors.Is(err, translog.ErrConsistency):
		return "das Transparenzlog bestätigt den Zustand nicht"
	case errors.Is(err, translog.ErrNotInLog), errors.Is(err, translog.ErrMismatch), errors.Is(err, translog.ErrOrder),
		errors.Is(err, translog.ErrSuperseded), errors.Is(err, translog.ErrPrerequisite):
		return "nicht im Transparenzlog oder im Widerspruch dazu"
	case errors.Is(err, store.ErrChain):
		return "die Epochenkette prüft nicht"
	case errors.Is(err, store.ErrNotFound), errors.Is(err, ErrNotFound):
		return "Datei fehlt"
	case errors.Is(err, store.ErrRecord), errors.Is(err, store.ErrTooLarge), errors.Is(err, envelope.ErrTooLarge),
		errors.Is(err, envelope.ErrMagic), errors.Is(err, envelope.ErrVersion), errors.Is(err, envelope.ErrTruncated),
		errors.Is(err, envelope.ErrHeader), errors.Is(err, envelope.ErrHeaderVersion), errors.Is(err, envelope.ErrHeaderSize),
		errors.Is(err, envelope.ErrRecipients), errors.Is(err, envelope.ErrRecipientsSize), errors.Is(err, envelope.ErrBlockSize),
		errors.Is(err, envelope.ErrEmptyBlock), errors.Is(err, envelope.ErrElementType), errors.Is(err, envelope.ErrElement),
		errors.Is(err, envelope.ErrTrailer), errors.Is(err, envelope.ErrTrailerSize):
		return "Format ungültig"
	case errors.Is(err, store.ErrNotRegular):
		// A directory, a FIFO, a device or a socket in place of a file
		// that is read (store.OpenRegular, store.OpenRegularIn) or of
		// a lock file (store: lock ... is not a regular file, from
		// openExistingLock: the lock of a mailbox, for example while a
		// file is signed again). The cause names no file, so for a
		// lock file it fits only loosely. Checked after every other
		// cause, so that it only names what was "Prüfung
		// fehlgeschlagen" before (task 28, Nr. 104) and a cause of the
		// step, such as errResign, wins (TestWarnCause).
		return causeUnreadable
	default:
		return "Prüfung fehlgeschlagen"
	}
}
