package dataact

import (
	"archive/zip"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ValidateBundle verifies manifest file digests and the ECDSA signature.
// When trustCert is non-nil, the manifest certificate must match it byte-for-byte.
func ValidateBundle(bundlePath string, trustCert *x509.Certificate) (Manifest, error) {
	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		return Manifest{}, fmt.Errorf("dataact: open bundle: %w", err)
	}
	defer reader.Close()

	manifest, err := readManifest(reader)
	if err != nil {
		return Manifest{}, err
	}
	if manifest.SchemaVersion == "" {
		return Manifest{}, fmt.Errorf("dataact: missing manifest in bundle")
	}
	if manifest.SchemaVersion != SchemaVersion {
		return Manifest{}, fmt.Errorf("dataact: unsupported schema version %q", manifest.SchemaVersion)
	}

	signedDigest, err := hex.DecodeString(manifest.BundleSHA256)
	if err != nil {
		return Manifest{}, fmt.Errorf("dataact: decode bundleSha256: %w", err)
	}
	computed := contentDigest(manifest.Files)
	if string(computed) != string(signedDigest) {
		return Manifest{}, fmt.Errorf("dataact: bundle digest mismatch")
	}

	for _, entry := range manifest.Files {
		if entry.Name == FileManifest {
			continue
		}
		sum, rows, err := digestZipEntry(reader, entry.Name)
		if err != nil {
			return Manifest{}, err
		}
		if entry.SHA256 != sum {
			return Manifest{}, fmt.Errorf("dataact: digest mismatch for %s", entry.Name)
		}
		if strings.HasSuffix(entry.Name, ".ndjson") && entry.Rows != rows {
			return Manifest{}, fmt.Errorf("dataact: row count mismatch for %s", entry.Name)
		}
	}

	if manifest.Signature == "" {
		return Manifest{}, fmt.Errorf("dataact: missing bundle signature")
	}
	payload := contentCanonical(manifest.Files)
	if err := verifyManifestSignature(manifest, payload, trustCert); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func readManifest(reader *zip.ReadCloser) (Manifest, error) {
	for _, file := range reader.File {
		if file.Name != FileManifest {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return Manifest{}, fmt.Errorf("dataact: open manifest: %w", err)
		}
		defer rc.Close()
		var manifest Manifest
		if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
			return Manifest{}, fmt.Errorf("dataact: decode manifest: %w", err)
		}
		return manifest, nil
	}
	return Manifest{}, fmt.Errorf("dataact: missing manifest in bundle")
}

func digestZipEntry(reader *zip.ReadCloser, name string) (string, int, error) {
	for _, file := range reader.File {
		if file.Name != name {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return "", 0, err
		}
		defer rc.Close()
		hasher := sha256.New()
		rows := 0
		if strings.HasSuffix(name, ".ndjson") {
			payload, err := io.ReadAll(rc)
			if err != nil {
				return "", 0, err
			}
			if len(payload) > 0 {
				if _, err := hasher.Write(payload); err != nil {
					return "", 0, err
				}
				for _, line := range strings.Split(string(payload), "\n") {
					if strings.TrimSpace(line) != "" {
						rows++
					}
				}
			}
		} else {
			if _, err := io.Copy(hasher, rc); err != nil {
				return "", 0, err
			}
			rows = 1
		}
		return hex.EncodeToString(hasher.Sum(nil)), rows, nil
	}
	return "", 0, fmt.Errorf("dataact: file %s not found in bundle", name)
}

func verifyManifestSignature(manifest Manifest, payload []byte, trustCert *x509.Certificate) error {
	sig, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return fmt.Errorf("dataact: decode signature: %w", err)
	}
	certDER, err := base64.StdEncoding.DecodeString(manifest.CertificateDER)
	if err != nil {
		return fmt.Errorf("dataact: decode certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("dataact: parse certificate: %w", err)
	}
	if trustCert != nil && !cert.Equal(trustCert) {
		return fmt.Errorf("dataact: manifest certificate does not match trusted certificate")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("dataact: certificate public key is not ECDSA")
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("dataact: invalid bundle signature")
	}
	return nil
}
