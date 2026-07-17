package dataact

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"time"
)

// testBundleSigner signs export bundles in tests and fixture generation.
type testBundleSigner struct {
	key     *ecdsa.PrivateKey
	certDER []byte
}

func (s testBundleSigner) sign(ctx context.Context, digest []byte) ([]byte, error) {
	_ = ctx
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

func (s testBundleSigner) keyID() string {
	return "test-signing-key"
}

// BuildTestBundle writes a signed minimal export bundle to destPath.
func BuildTestBundle(destPath string, tenantID string, devices []DeviceRecord, profileStates []ProfileStateRecord, journal []JournalRecord, anchor JournalChainAnchor) error {
	signer, err := newTestBundleSigner()
	if err != nil {
		return err
	}
	return buildSignedBundle(destPath, tenantID, devices, profileStates, journal, anchor, signer)
}

func newTestBundleSigner() (testBundleSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return testBundleSigner{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "OpenIoTRSP Data Act test",
			Organization: []string{"OpenIoTRSP"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return testBundleSigner{}, err
	}
	return testBundleSigner{key: key, certDER: certDER}, nil
}

func buildSignedBundle(destPath, tenantID string, devices []DeviceRecord, profileStates []ProfileStateRecord, journal []JournalRecord, anchor JournalChainAnchor, signer testBundleSigner) error {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		ExportID:      "test-export",
		TenantID:      tenantID,
		ExportedAt:    time.Now().UTC().Truncate(time.Microsecond),
		EIMID:         "openiotrsp.eim.test",
		JournalChain:  anchor,
	}

	tenantJSON, err := json.MarshalIndent(map[string]string{
		"id":   tenantID,
		"name": tenantID,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeZipBytes(zw, FileTenant, tenantJSON, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileSIMs, []any{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileDevices, devices, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileProfileState, profileStates, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileAssociatedEIM, []AssociatedEIMRecord{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileEUICCState, []EUICCStateRecord{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileOperations, []OperationRecord{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileNotifications, []NotificationRecord{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileFallbackPolicy, []any{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileProfileLabels, []any{}, &manifest); err != nil {
		return err
	}
	if err := writeZipNDJSON(zw, FileCommandJournal, journal, &manifest); err != nil {
		return err
	}
	if err := writeZipBytes(zw, FileREADME, []byte("# test bundle\n"), &manifest); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}

	manifest.BundleSHA256 = hex.EncodeToString(contentDigest(manifest.Files))
	payload := contentCanonical(manifest.Files)
	sig, err := signer.sign(context.Background(), sha256Sum(payload))
	if err != nil {
		return err
	}
	manifest.SigningKeyID = signer.keyID()
	manifest.Signature = base64.StdEncoding.EncodeToString(sig)
	manifest.CertificateDER = base64.StdEncoding.EncodeToString(signer.certDER)

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return writeZipWithManifest(buf.Bytes(), destPath, manifestBytes)
}

func writeZipBytes(zw *zip.Writer, name string, payload []byte, manifest *Manifest) error {
	fw, err := zw.Create(name)
	if err != nil {
		return err
	}
	if _, err := fw.Write(payload); err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:   name,
		Rows:   1,
		SHA256: hex.EncodeToString(sum[:]),
	})
	return nil
}

func writeZipNDJSON[T any](zw *zip.Writer, name string, rows []T, manifest *Manifest) error {
	fw, err := zw.Create(name)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	count := 0
	for _, row := range rows {
		payload, err := json.Marshal(row)
		if err != nil {
			return err
		}
		if _, err := hasher.Write(payload); err != nil {
			return err
		}
		if _, err := fw.Write(payload); err != nil {
			return err
		}
		if _, err := fw.Write([]byte("\n")); err != nil {
			return err
		}
		if _, err := hasher.Write([]byte("\n")); err != nil {
			return err
		}
		count++
	}
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:   name,
		Rows:   count,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	})
	return nil
}

func writeZipWithManifest(zipBytes []byte, destPath string, manifestBytes []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			return err
		}
		payload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
		fw, err := zw.Create(file.Name)
		if err != nil {
			return err
		}
		if _, err := fw.Write(payload); err != nil {
			return err
		}
	}
	fw, err := zw.Create(FileManifest)
	if err != nil {
		return err
	}
	if _, err := fw.Write(manifestBytes); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(destPath, buf.Bytes(), 0o644)
}

func sha256Sum(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return sum[:]
}
