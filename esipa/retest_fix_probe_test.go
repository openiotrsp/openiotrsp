package esipa

// Retest probes for the advisory-fix-1 branch (8958544). Each test asserts that
// the defence holds, so PASS means the fix covers that path. Every probe runs on
// the in-memory store and, when OPENIOTRSP_POSTGRES_TEST_DSN is set, on a freshly
// migrated Postgres store as well.
// All identities and state are local/synthetic; no eUICC or network is contacted.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
	"github.com/openiotrsp/openiotrsp/pki"
	"github.com/openiotrsp/openiotrsp/storage"
	"github.com/openiotrsp/openiotrsp/storage/memory"
	storepg "github.com/openiotrsp/openiotrsp/storage/postgres"
)

type retestStoreFactory struct {
	name string
	open func(t *testing.T) storage.Store
}

func retestStoreFactories(t *testing.T) []retestStoreFactory {
	factories := []retestStoreFactory{{"memory", func(*testing.T) storage.Store { return memory.New() }}}
	dsn := os.Getenv("OPENIOTRSP_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Log("OPENIOTRSP_POSTGRES_TEST_DSN not set: Postgres store not exercised")
		return factories
	}
	return append(factories, retestStoreFactory{"postgres", func(t *testing.T) storage.Store {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
			t.Fatal(err)
		}
		pool.Close()
		abs, err := filepath.Abs("../migrations")
		if err != nil {
			t.Fatal(err)
		}
		dbURL, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		dbURL.Scheme = "pgx5"
		m, err := migrate.New((&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String(), dbURL.String())
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Fatal(err)
		}
		_, _ = m.Close()
		store, err := storepg.Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Close)
		return store
	}})
}

type retestEnv struct {
	t        *testing.T
	ctx      context.Context
	store    storage.Store
	handler  *Handler
	fixture  *pki.SGP26VariantONISTMaterial
	eid      string
	eidValue []byte
	iccid    []byte
}

func newRetestEnv(t *testing.T, store storage.Store, verify bool) *retestEnv {
	t.Helper()
	ctx := context.Background()
	fixture, err := pki.LoadSGP26VariantONISTMaterial("")
	if err != nil {
		t.Fatal(err)
	}
	eidValue, err := hex.DecodeString(fixture.EID)
	if err != nil {
		t.Fatal(err)
	}
	env := &retestEnv{t: t, ctx: ctx, store: store, fixture: fixture, eid: fixture.EID, eidValue: eidValue, iccid: []byte{0x89, 0x10}}
	if err := store.RegisterDevice(ctx, storage.DefaultTenantID, storage.Device{EID: env.eid}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetProfileState(ctx, storage.DefaultTenantID, storage.ProfileState{EID: env.eid, ICCID: hex.EncodeToString(env.iccid), IsEnabled: false}); err != nil {
		t.Fatal(err)
	}
	env.handler = NewHandler(store, storage.DefaultTenantID)
	if verify {
		resolver, err := NewStaticEUICCCertificateResolver(fixture.CICertificate, fixture.EUMCertificate, fixture.EUICCCertificate, pki.WithCurrentTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)))
		if err != nil {
			t.Fatal(err)
		}
		env.handler.EUICCPublicKey = resolver
	} else {
		env.handler.AllowUnverifiedEUICCPackageResults = true
	}
	return env
}

// queue enqueues a PSMO package and returns the matching eUICC-signed result.
func (e *retestEnv) queue(op protocolasn1.PsmoOperation, counter int64, txn byte, resultTag uint64) (*protocolasn1.EuiccPackageRequest, []byte, int64) {
	request := samplePSMOEuiccPackageRequest(e.eidValue, op, 3)
	request.EuiccPackageSigned.EuiccPackage.PSMOs[0].ICCID = cloneBytes(e.iccid)
	request.EuiccPackageSigned.CounterValue = counter
	request.EuiccPackageSigned.EimTransactionID = []byte{txn}
	queued, err := e.store.EnqueueOperation(e.ctx, storage.DefaultTenantID, storage.OperationRequest{EID: e.eid, Kind: storage.OperationEuiccPackage, Payload: encode(e.t, request)})
	if err != nil {
		e.t.Fatal(err)
	}
	return request, signedEUICCPackageResult(e.t, e.fixture.EUICCKey, request, counter+10, resultTag, 0), queued.ID
}

// provide sends one ProvideEimPackageResult over the chosen binding and returns
// the HTTP status.
func (e *retestEnv) provide(binding string, result protocolasn1.EimPackageResult) int {
	provide := &protocolasn1.ProvideEimPackageResult{EID: e.eidValue, EimPackageResult: result}
	var request *http.Request
	switch binding {
	case "asn1":
		request = httptest.NewRequest(http.MethodPost, GSMAPathASN1, bytes.NewReader(encodeEnvelope(e.t, provide)))
		request.Header.Set("Content-Type", ASN1MediaType)
	case "json-provide", "json-notify":
		der, err := protocolasn1.Encode(provide)
		if err != nil {
			e.t.Fatal(err)
		}
		path, body := GSMAPathProvideEimPackageResult, map[string]string{"eimPackageResult": base64.StdEncoding.EncodeToString(der)}
		if binding == "json-notify" {
			path, body = GSMAPathHandleNotification, map[string]string{"provideEimPackageResult": base64.StdEncoding.EncodeToString(der)}
		}
		raw, _ := json.Marshal(body)
		request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
	default:
		e.t.Fatalf("unknown binding %q", binding)
	}
	response := httptest.NewRecorder()
	e.handler.HTTPHandler().ServeHTTP(response, request)
	return response.Code
}

func (e *retestEnv) ipaError(binding string, txn []byte) int {
	return e.provide(binding, protocolasn1.EimPackageResult{
		Kind:  protocolasn1.EimPackageResultError,
		Error: &protocolasn1.EimPackageResultResponseError{EimTransactionID: txn, Code: 127},
	})
}

func (e *retestEnv) submit(binding string, result []byte) int {
	return e.provide(binding, protocolasn1.EimPackageResult{Raw: mustTLVFromDER(e.t, result)})
}

func (e *retestEnv) enabled() bool {
	profile, err := e.store.GetProfileState(e.ctx, storage.DefaultTenantID, e.eid, hex.EncodeToString(e.iccid))
	if err != nil {
		e.t.Fatal(err)
	}
	return profile.IsEnabled
}

func (e *retestEnv) status(id int64) storage.OperationStatus {
	operation, err := e.store.GetOperation(e.ctx, storage.DefaultTenantID, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return operation.Status
}

func (e *retestEnv) poll() protocolasn1.GetEimPackageResponse {
	request := httptest.NewRequest(http.MethodPost, GSMAPathASN1, bytes.NewReader(encodeEnvelope(e.t, &protocolasn1.GetEimPackageRequest{EID: e.eidValue})))
	request.Header.Set("Content-Type", ASN1MediaType)
	response := httptest.NewRecorder()
	e.handler.HTTPHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		e.t.Fatalf("poll HTTP %d: %s", response.Code, response.Body.String())
	}
	return decodeGetResponse(e.t, response.Body.Bytes())
}

// Chain from the v0.2.29 retest, over every binding and store: an unsigned IPA
// eimPackageError naming a completed operation must not reopen it, and the old
// signed result must not apply again.
func TestFixRetestChainBlockedAllBindings(t *testing.T) {
	for _, factory := range retestStoreFactories(t) {
		for _, binding := range []string{"asn1", "json-provide", "json-notify"} {
			t.Run(factory.name+"/"+binding, func(t *testing.T) {
				e := newRetestEnv(t, factory.open(t), true)
				_, enableResult, enableID := e.queue(protocolasn1.PsmoEnable, 1, 0x11, 3)
				e.submit("asn1", enableResult)
				_, disableResult, disableID := e.queue(protocolasn1.PsmoDisable, 2, 0x22, 4)
				e.submit("asn1", disableResult)
				if e.enabled() || e.status(enableID) != storage.OperationDone || e.status(disableID) != storage.OperationDone {
					t.Fatal("setup: expected profile disabled and both operations done")
				}
				code := e.ipaError(binding, []byte{0x11})
				t.Logf("unsigned IPA eimPackageError txn=11 via %s: HTTP %d, enable op=%s", binding, code, e.status(enableID))
				if e.status(enableID) != storage.OperationDone {
					t.Fatalf("completed operation reopened: %s", e.status(enableID))
				}
				replay := e.submit("asn1", enableResult)
				t.Logf("replay old signed enable: HTTP %d, profile enabled=%v, enable op=%s, disable op=%s", replay, e.enabled(), e.status(enableID), e.status(disableID))
				if e.enabled() {
					t.Fatal("old signed enable applied again")
				}
			})
		}
	}
}

// An unsigned IPA error on a pending operation, with and without a transaction
// ID, must leave it queued; the next poll must re-deliver the same package, and a
// genuine signed result must still complete it and apply its state.
func TestFixRetestIPAErrorRetriesThenGenuineResultCompletes(t *testing.T) {
	for _, factory := range retestStoreFactories(t) {
		for _, withTxn := range []bool{true, false} {
			name := factory.name + "/no-txn"
			if withTxn {
				name = factory.name + "/matching-txn"
			}
			t.Run(name, func(t *testing.T) {
				e := newRetestEnv(t, factory.open(t), true)
				request, enableResult, enableID := e.queue(protocolasn1.PsmoEnable, 1, 0x11, 3)
				first := e.poll()
				if first.Kind != protocolasn1.GetEimPackageEuiccPackageRequest {
					t.Fatalf("first poll kind=%v", first.Kind)
				}
				var txn []byte
				if withTxn {
					txn = []byte{0x11}
				}
				code := e.ipaError("asn1", txn)
				next := e.poll()
				t.Logf("IPA error (txn=%x): HTTP %d, op=%s, next poll kind=%v", txn, code, e.status(enableID), next.Kind)
				if e.status(enableID) != storage.OperationPending {
					t.Fatalf("operation closed by unsigned IPA error: %s", e.status(enableID))
				}
				if next.Kind != protocolasn1.GetEimPackageEuiccPackageRequest ||
					!bytes.Equal(next.EuiccPackageRequest.EuiccPackageSigned.EimTransactionID, request.EuiccPackageSigned.EimTransactionID) {
					t.Fatalf("next poll did not re-deliver the queued package: %#v", next)
				}
				e.submit("asn1", enableResult)
				t.Logf("genuine signed result after retry: op=%s, profile enabled=%v", e.status(enableID), e.enabled())
				if e.status(enableID) != storage.OperationDone || !e.enabled() {
					t.Fatal("genuine signed result no longer completes the operation")
				}
			})
		}
	}
}

// Unverified-result mode (the documented test/demo escape hatch): error results
// must still not move a completed operation out of done, so the replay chain must
// not work there either.
func TestFixRetestUnverifiedModeKeepsCompletedOperationDone(t *testing.T) {
	for _, factory := range retestStoreFactories(t) {
		t.Run(factory.name, func(t *testing.T) {
			e := newRetestEnv(t, factory.open(t), false)
			request, enableResult, enableID := e.queue(protocolasn1.PsmoEnable, 1, 0x11, 3)
			e.submit("asn1", enableResult)
			_, disableResult, disableID := e.queue(protocolasn1.PsmoDisable, 2, 0x22, 4)
			e.submit("asn1", disableResult)
			if e.enabled() || e.status(enableID) != storage.OperationDone || e.status(disableID) != storage.OperationDone {
				t.Fatal("setup: expected profile disabled and both operations done")
			}

			ipa := e.ipaError("asn1", []byte{0x11})
			t.Logf("unverified mode, IPA eimPackageError txn=11: HTTP %d, enable op=%s", ipa, e.status(enableID))
			if e.status(enableID) != storage.OperationDone {
				t.Fatalf("IPA error reopened a completed operation: %s", e.status(enableID))
			}

			code := protocolasn1.EuiccPackageUnsignedErrorCode(127)
			unsigned := &protocolasn1.EuiccPackageResult{
				Kind: protocolasn1.EuiccPackageResultErrorUnsigned,
				ErrorUnsigned: &protocolasn1.EuiccPackageErrorUnsigned{
					EimID:            request.EuiccPackageSigned.EimID,
					EimTransactionID: []byte{0x11},
					ErrorCode:        &code,
				},
			}
			eu := e.provide("asn1", protocolasn1.EimPackageResult{Raw: mustTLV(t, unsigned)})
			t.Logf("unverified mode, EuiccPackageErrorUnsigned txn=11: HTTP %d, enable op=%s", eu, e.status(enableID))
			if e.status(enableID) != storage.OperationDone {
				t.Fatalf("unsigned eUICC error reopened a completed operation: %s", e.status(enableID))
			}

			e.submit("asn1", enableResult)
			t.Logf("replay old enable: profile enabled=%v", e.enabled())
			if e.enabled() {
				t.Fatal("old enable applied again in unverified mode")
			}
		})
	}
}
