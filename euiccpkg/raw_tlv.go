package euiccpkg

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	tagEuiccPackageResult = []byte{0xbf, 0x51}
	tagSequence           = []byte{0x30}
	tagSignature          = []byte{0x5f, 0x37}
	tagInteger            = []byte{0x02}
	tagContext0           = []byte{0x80}
	tagContext1           = []byte{0x81}
	tagContext2           = []byte{0x82}
	tagContext3           = []byte{0x83}
)

type tlvSpan struct {
	tagStart   int
	valueStart int
	valueEnd   int
	end        int
	tag        []byte
}

func rawSignedDataFromResultDER(data []byte) ([]byte, error) {
	root, err := parseTLVSpan(data, 0)
	if err != nil {
		return nil, err
	}
	if root.end != len(data) {
		return nil, errors.New("euiccpkg: trailing data after eUICC package result")
	}
	if !bytes.Equal(root.tag, tagEuiccPackageResult) {
		return nil, fmt.Errorf("euiccpkg: result tag %x, want %x", root.tag, tagEuiccPackageResult)
	}

	selected, err := onlyChild(data, root)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(selected.tag, tagSequence) {
		return nil, nil
	}
	children, err := children(data, selected)
	if err != nil {
		return nil, err
	}
	if len(children) == 0 {
		return nil, errors.New("euiccpkg: signed result child is empty")
	}
	if !hasSpanTag(children[len(children)-1], tagSignature) {
		return nil, nil
	}
	if len(children) != 2 {
		return nil, errors.New("euiccpkg: signed result requires signed data and signature")
	}
	signedData := children[0]
	if err := validateResultSignedData(data, signedData); err != nil {
		return nil, err
	}
	return cloneBytes(data[signedData.tagStart:signedData.end]), nil
}

func onlyChild(data []byte, parent tlvSpan) (tlvSpan, error) {
	child, err := parseTLVSpan(data, parent.valueStart)
	if err != nil {
		return tlvSpan{}, err
	}
	if child.end != parent.valueEnd {
		return tlvSpan{}, errors.New("euiccpkg: expected exactly one selected result child")
	}
	return child, nil
}

func children(data []byte, parent tlvSpan) ([]tlvSpan, error) {
	out := []tlvSpan{}
	for offset := parent.valueStart; offset < parent.valueEnd; {
		child, err := parseTLVSpan(data, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, child)
		offset = child.end
	}
	return out, nil
}

func validateResultSignedData(data []byte, signedData tlvSpan) error {
	if !hasSpanTag(signedData, tagSequence) {
		return errors.New("euiccpkg: signed result data must be a SEQUENCE")
	}
	fields, err := children(data, signedData)
	if err != nil {
		return err
	}
	if isPackageResultDataSigned(fields) || isPackageErrorDataSigned(fields) {
		return nil
	}
	return errors.New("euiccpkg: signed data is not an SGP.32 eUICC package result payload")
}

func isPackageResultDataSigned(fields []tlvSpan) bool {
	index, ok := signedDataPrefix(fields)
	if !ok {
		return false
	}
	if index >= len(fields) || !hasSpanTag(fields[index], tagContext3) {
		return false
	}
	index++
	return index == len(fields)-1 && hasSpanTag(fields[index], tagSequence)
}

func isPackageErrorDataSigned(fields []tlvSpan) bool {
	index, ok := signedDataPrefix(fields)
	if !ok {
		return false
	}
	return index == len(fields)-1 && hasSpanTag(fields[index], tagInteger)
}

func signedDataPrefix(fields []tlvSpan) (int, bool) {
	if len(fields) < 3 || !hasSpanTag(fields[0], tagContext0) || !hasSpanTag(fields[1], tagContext1) {
		return 0, false
	}
	index := 2
	if hasSpanTag(fields[index], tagContext2) {
		index++
	}
	return index, index < len(fields)
}

func hasSpanTag(span tlvSpan, tag []byte) bool {
	return bytes.Equal(span.tag, tag)
}

func parseTLVSpan(data []byte, offset int) (tlvSpan, error) {
	if offset < 0 || offset >= len(data) {
		return tlvSpan{}, errors.New("euiccpkg: missing TLV")
	}
	tagStart := offset
	offset++
	if data[tagStart]&0x1f == 0x1f {
		for {
			if offset >= len(data) {
				return tlvSpan{}, errors.New("euiccpkg: truncated high-tag-number TLV")
			}
			b := data[offset]
			offset++
			if b&0x80 == 0 {
				break
			}
		}
	}
	tag := data[tagStart:offset]
	if offset >= len(data) {
		return tlvSpan{}, errors.New("euiccpkg: missing TLV length")
	}

	lengthByte := data[offset]
	offset++
	var length int
	switch {
	case lengthByte < 0x80:
		length = int(lengthByte)
	case lengthByte == 0x80:
		return tlvSpan{}, errors.New("euiccpkg: indefinite-length TLV is not supported")
	default:
		lengthBytes := int(lengthByte & 0x7f)
		if lengthBytes == 0 {
			return tlvSpan{}, errors.New("euiccpkg: invalid TLV length")
		}
		if lengthBytes > 4 {
			return tlvSpan{}, errors.New("euiccpkg: TLV length too large")
		}
		if offset+lengthBytes > len(data) {
			return tlvSpan{}, errors.New("euiccpkg: truncated TLV length")
		}
		for range lengthBytes {
			length = length<<8 | int(data[offset])
			offset++
		}
	}
	if length < 0 || offset+length > len(data) {
		return tlvSpan{}, errors.New("euiccpkg: truncated TLV value")
	}
	return tlvSpan{
		tagStart:   tagStart,
		valueStart: offset,
		valueEnd:   offset + length,
		end:        offset + length,
		tag:        tag,
	}, nil
}
