package asn1

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"io"

	"github.com/damonto/euicc-go/bertlv"
	"github.com/damonto/euicc-go/bertlv/primitive"
)

var errUnexpectedTag = errors.New("unexpected BER-TLV tag")

// Marshaler is implemented by SGP.32 structures that can encode themselves as
// BER-TLV.
type Marshaler interface {
	MarshalBERTLV() (*bertlv.TLV, error)
}

// Unmarshaler is implemented by SGP.32 structures that can decode themselves
// from BER-TLV.
type Unmarshaler interface {
	UnmarshalBERTLV(*bertlv.TLV) error
}

// Encode returns the DER-compatible BER-TLV bytes for a structure.
func Encode(value Marshaler) ([]byte, error) {
	if value == nil {
		return nil, errors.New("asn1: cannot encode nil value")
	}
	tlv, err := value.MarshalBERTLV()
	if err != nil {
		return nil, err
	}
	if tlv == nil {
		return nil, errors.New("asn1: marshaler returned nil TLV")
	}
	encoded, err := tlv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("asn1: marshal TLV: %w", err)
	}
	return encoded, nil
}

// Decode parses one BER-TLV object from data and stores it in value.
func Decode(data []byte, value Unmarshaler) error {
	if value == nil {
		return errors.New("asn1: cannot decode into nil value")
	}
	tlv, err := parseTLV(data)
	if err != nil {
		return err
	}
	return value.UnmarshalBERTLV(tlv)
}

func parseTLV(data []byte) (*bertlv.TLV, error) {
	if len(data) == 0 {
		return nil, errors.New("asn1: empty BER-TLV input")
	}
	reader := bytes.NewReader(data)
	tlv := new(bertlv.TLV)
	n, err := tlv.ReadFrom(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("asn1: truncated BER-TLV input: %w", err)
		}
		return nil, fmt.Errorf("asn1: parse BER-TLV: %w", err)
	}
	if n != int64(len(data)) || reader.Len() != 0 {
		return nil, errors.New("asn1: trailing data after BER-TLV object")
	}
	return tlv, nil
}

func cloneTLV(tlv *bertlv.TLV) *bertlv.TLV {
	if tlv == nil {
		return nil
	}
	return tlv.Clone()
}

func expectTag(tlv *bertlv.TLV, tag bertlv.Tag) error {
	if tlv == nil {
		return fmt.Errorf("%w: missing %s", errUnexpectedTag, tag.String())
	}
	if !tlv.Tag.Equal(tag) {
		return fmt.Errorf("%w: got %s, want %s", errUnexpectedTag, tlv.Tag.String(), tag.String())
	}
	return nil
}

func hasTag(tlv *bertlv.TLV, tag bertlv.Tag) bool {
	return tlv != nil && tlv.Tag.Equal(tag)
}

func constructed(tag bertlv.Tag, children ...*bertlv.TLV) *bertlv.TLV {
	return bertlv.NewChildren(tag, children...)
}

func rawChild(tlv *bertlv.TLV) *bertlv.TLV {
	return cloneTLV(tlv)
}

func integerTLV[Int signedInteger](tag bertlv.Tag, value Int) (*bertlv.TLV, error) {
	return marshalValue(tag, primitive.MarshalInt(value))
}

func integerValue[Int signedInteger](tlv *bertlv.TLV) (Int, error) {
	var value Int
	if tlv == nil {
		return value, errors.New("asn1: missing INTEGER")
	}
	if err := tlv.UnmarshalValue(primitive.UnmarshalInt(&value)); err != nil {
		return value, fmt.Errorf("asn1: decode INTEGER: %w", err)
	}
	return value, nil
}

func utf8TLV(tag bertlv.Tag, value string) *bertlv.TLV {
	return bertlv.NewValue(tag, []byte(value))
}

func utf8Value(tlv *bertlv.TLV) (string, error) {
	if tlv == nil {
		return "", errors.New("asn1: missing UTF8String")
	}
	return string(tlv.Value), nil
}

func octetTLV(tag bertlv.Tag, value []byte) *bertlv.TLV {
	return bertlv.NewValue(tag, copyBytes(value))
}

func octetValue(tlv *bertlv.TLV) ([]byte, error) {
	if tlv == nil {
		return nil, errors.New("asn1: missing OCTET STRING")
	}
	return copyBytes(tlv.Value), nil
}

func nullTLV(tag bertlv.Tag) *bertlv.TLV {
	return bertlv.NewValue(tag, nil)
}

func bitStringTLV(tag bertlv.Tag, bits []bool) *bertlv.TLV {
	return bertlv.NewValue(tag, marshalBitString(bits))
}

func bitStringValue(tlv *bertlv.TLV) ([]bool, error) {
	if tlv == nil {
		return nil, errors.New("asn1: missing BIT STRING")
	}
	return unmarshalBitString(tlv.Value)
}

func booleanTLV(tag bertlv.Tag, value bool) (*bertlv.TLV, error) {
	return marshalValue(tag, primitive.MarshalBool(value))
}

func booleanValue(tlv *bertlv.TLV) (bool, error) {
	var value bool
	if tlv == nil {
		return false, errors.New("asn1: missing BOOLEAN")
	}
	if err := tlv.UnmarshalValue(primitive.UnmarshalBool(&value)); err != nil {
		return false, fmt.Errorf("asn1: decode BOOLEAN: %w", err)
	}
	return value, nil
}

func marshalValue(tag bertlv.Tag, value encoding.BinaryMarshaler) (*bertlv.TLV, error) {
	tlv, err := bertlv.MarshalValue(tag, value)
	if err != nil {
		return nil, err
	}
	return tlv, nil
}

func marshalBitString(bits []bool) []byte {
	if len(bits) == 0 {
		return []byte{0}
	}
	unusedBits := (8 - len(bits)%8) % 8
	data := make([]byte, 1+(len(bits)+7)/8)
	data[0] = byte(unusedBits)
	for index, bit := range bits {
		if bit {
			data[1+index/8] |= 1 << (7 - byte(index%8))
		}
	}
	return data
}

func unmarshalBitString(data []byte) ([]bool, error) {
	if len(data) == 0 {
		return nil, errors.New("asn1: BIT STRING missing unused-bit octet")
	}
	unusedBits := int(data[0])
	if unusedBits > 7 || len(data) == 1 && unusedBits != 0 {
		return nil, errors.New("asn1: invalid BIT STRING unused-bit count")
	}
	if len(data) > 1 && unusedBits > 0 {
		mask := byte((1 << unusedBits) - 1)
		if data[len(data)-1]&mask != 0 {
			return nil, errors.New("asn1: non-zero BIT STRING padding bits")
		}
	}
	bitLength := (len(data)-1)*8 - unusedBits
	bits := make([]bool, bitLength)
	for index := range bitLength {
		bits[index] = data[1+index/8]&(1<<(7-byte(index%8))) != 0
	}
	return bits, nil
}

func copyBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	copied := make([]byte, len(value))
	copy(copied, value)
	return copied
}

type signedInteger interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}
