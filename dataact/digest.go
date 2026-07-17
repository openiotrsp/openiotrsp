package dataact

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

func contentDigest(files []ManifestFile) []byte {
	sum := sha256.Sum256(contentCanonical(files))
	return sum[:]
}

func contentCanonical(files []ManifestFile) []byte {
	sorted := append([]ManifestFile(nil), files...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})
	buf := make([]byte, 0, len(sorted)*40)
	for _, file := range sorted {
		buf = append(buf, file.Name...)
		buf = append(buf, 0)
		digest, err := hex.DecodeString(file.SHA256)
		if err != nil {
			continue
		}
		buf = append(buf, digest...)
	}
	return buf
}
