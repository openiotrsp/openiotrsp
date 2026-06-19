package esipa

import (
	"encoding/hex"
	"log/slog"

	"github.com/damonto/euicc-go/bertlv"
	protocolasn1 "github.com/openiotrsp/openiotrsp/asn1"
)

func logProvideResultDecodeFailed(logger *slog.Logger, requestBytes []byte, tlv *bertlv.TLV, err error) {
	if logger == nil {
		return
	}
	attrs := []any{
		"error", err,
		"first_tlv_tag_hex", firstTLVTagHex(tlv),
	}
	if len(requestBytes) > 0 {
		attrs = append(attrs, "request_bytes", hex.EncodeToString(requestBytes))
	}
	logger.Warn("provideResult decode failed", attrs...)
}

func logProvideResultOutcome(logger *slog.Logger, eid string, result *protocolasn1.EuiccPackageResult) {
	if logger == nil || result == nil {
		return
	}
	switch result.Kind {
	case protocolasn1.EuiccPackageResultOK:
		seq := int64(0)
		if result.Signed != nil {
			seq = result.Signed.Data.SeqNumber
		}
		logger.Info("provideResult recorded",
			"eid", eid,
			"result_kind", "ok",
			"seq_number", seq,
		)
	case protocolasn1.EuiccPackageResultErrorUnsigned:
		attrs := []any{"eid", eid, "result_kind", "unsigned_error"}
		if data := result.ErrorUnsigned; data != nil {
			attrs = append(attrs,
				"eim_id", data.EimID,
				"transaction_id_hex", hex.EncodeToString(data.EimTransactionID),
			)
			if data.ErrorCode != nil {
				attrs = append(attrs, "unsigned_error_code", int64(*data.ErrorCode))
			} else {
				attrs = append(attrs, "unsigned_error_code", "missing")
			}
			if data.AssociationToken != nil {
				attrs = append(attrs, "association_token_in_error", *data.AssociationToken)
			}
		}
		logger.Info("provideResult recorded", attrs...)
	case protocolasn1.EuiccPackageResultErrorSigned:
		code := int64(0)
		if result.ErrorSigned != nil {
			code = int64(result.ErrorSigned.Data.ErrorCode)
		}
		logger.Info("provideResult recorded",
			"eid", eid,
			"result_kind", "signed_error",
			"package_error_code", code,
		)
	}
}

func logIpaEuiccDataError(logger *slog.Logger, eid string, response *protocolasn1.IpaEuiccDataResponse) {
	if logger == nil || response == nil || response.Error == nil {
		return
	}
	logger.Info("provideResult recorded",
		"eid", eid,
		"result_kind", "ipa_data_error",
		"ipa_error_code", int64(response.Error.Code),
	)
}

func firstTLVTagHex(tlv *bertlv.TLV) string {
	if tlv == nil {
		return ""
	}
	return hex.EncodeToString(tlv.Tag)
}
