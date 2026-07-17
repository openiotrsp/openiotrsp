package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/openiotrsp/openiotrsp/dataact"
	"github.com/openiotrsp/openiotrsp/storage"
)

// ImportBundle writes validated bundle entities for one tenant in a single transaction.
func (s *Store) ImportBundle(ctx context.Context, tenantID storage.TenantID, bundle *dataact.BundlePayload) error {
	if bundle == nil {
		return fmt.Errorf("postgres import: nil bundle")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx)

	for _, device := range bundle.Devices {
		if err := importDevice(ctx, tx, tenantID, device); err != nil {
			return err
		}
	}
	for _, state := range bundle.EUICCStates {
		if err := importEUICCState(ctx, tx, tenantID, state); err != nil {
			return err
		}
	}
	for _, state := range bundle.ProfileStates {
		if err := importProfileState(ctx, tx, tenantID, state); err != nil {
			return err
		}
	}
	for _, associated := range bundle.AssociatedEIM {
		if err := importAssociatedEIM(ctx, tx, tenantID, associated); err != nil {
			return err
		}
	}
	for _, operation := range bundle.Operations {
		if err := importOperation(ctx, tx, tenantID, operation); err != nil {
			return err
		}
	}
	for _, notification := range bundle.Notifications {
		if err := importNotification(ctx, tx, tenantID, notification); err != nil {
			return err
		}
	}
	if err := syncImportSequences(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func importDevice(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, device dataact.DeviceRecord) error {
	createdAt, updatedAt := dataact.ImportTimestamps(device.CreatedAt, device.UpdatedAt)
	_, err := tx.Exec(ctx, `
		INSERT INTO devices (tenant_id, eid, next_sequence_number, next_euicc_package_counter, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, eid)
		DO UPDATE SET next_sequence_number = EXCLUDED.next_sequence_number,
			next_euicc_package_counter = EXCLUDED.next_euicc_package_counter,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`, tenantString(tenantID), device.EID, device.NextSequenceNumber, device.NextEUICCPackageCounter, createdAt, updatedAt)
	return err
}

func importProfileState(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, state dataact.ProfileStateRecord) error {
	createdAt, updatedAt := dataact.ImportTimestamps(state.CreatedAt, state.UpdatedAt)
	_, err := tx.Exec(ctx, `
		INSERT INTO profile_state (tenant_id, eid, iccid, is_enabled, is_fallback, smdp_address, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id, eid, iccid)
		DO UPDATE SET is_enabled = EXCLUDED.is_enabled,
			is_fallback = EXCLUDED.is_fallback,
			smdp_address = EXCLUDED.smdp_address,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`, tenantString(tenantID), state.EID, state.ICCID, state.IsEnabled, state.IsFallback, state.SMDPAddress, createdAt, updatedAt)
	return err
}

func importAssociatedEIM(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, associated dataact.AssociatedEIMRecord) error {
	payload, err := dataact.DecodeOptionalBase64(associated.ConfigPayload)
	if err != nil {
		return err
	}
	createdAt, updatedAt := dataact.ImportTimestamps(associated.CreatedAt, associated.UpdatedAt)
	_, err = tx.Exec(ctx, `
		INSERT INTO associated_eim (tenant_id, eid, eim_id, eim_id_type, config_payload, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, eid, eim_id)
		DO UPDATE SET eim_id_type = EXCLUDED.eim_id_type,
			config_payload = EXCLUDED.config_payload,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`, tenantString(tenantID), associated.EID, associated.EIMID, associated.EIMIDType, payload, createdAt, updatedAt)
	return err
}

func importEUICCState(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, state dataact.EUICCStateRecord) error {
	eidValue, err := dataact.DecodeOptionalBase64(state.EIDValue)
	if err != nil {
		return err
	}
	info1, err := dataact.DecodeOptionalBase64(state.EUICCInfo1)
	if err != nil {
		return err
	}
	info2, err := dataact.DecodeOptionalBase64(state.EUICCInfo2)
	if err != nil {
		return err
	}
	caps, err := dataact.DecodeOptionalBase64(state.IPACapabilities)
	if err != nil {
		return err
	}
	deviceInfo, err := dataact.DecodeOptionalBase64(state.DeviceInfo)
	if err != nil {
		return err
	}
	eumCert, err := dataact.DecodeOptionalBase64(state.EUMCertificate)
	if err != nil {
		return err
	}
	euiccCert, err := dataact.DecodeOptionalBase64(state.EUICCCertificate)
	if err != nil {
		return err
	}
	rawPayload, err := dataact.DecodeOptionalBase64(state.RawPayload)
	if err != nil {
		return err
	}
	identifiers, err := dataact.DecodeCertificateIdentifiers(state.CertificateIdentifiers)
	if err != nil {
		return err
	}
	encodedIdentifiers, err := json.Marshal(identifiers)
	if err != nil {
		return err
	}
	createdAt, updatedAt := dataact.ImportTimestamps(state.CreatedAt, state.UpdatedAt)
	_, err = tx.Exec(ctx, `
		INSERT INTO euicc_state (
			tenant_id, eid, eid_value, default_smdp_address, root_smds_address,
			euicc_info1, euicc_info2, ipa_capabilities, device_info,
			eum_certificate, euicc_certificate, certificate_identifiers, raw_payload,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (tenant_id, eid)
		DO UPDATE SET eid_value = EXCLUDED.eid_value,
			default_smdp_address = EXCLUDED.default_smdp_address,
			root_smds_address = EXCLUDED.root_smds_address,
			euicc_info1 = EXCLUDED.euicc_info1,
			euicc_info2 = EXCLUDED.euicc_info2,
			ipa_capabilities = EXCLUDED.ipa_capabilities,
			device_info = EXCLUDED.device_info,
			eum_certificate = EXCLUDED.eum_certificate,
			euicc_certificate = EXCLUDED.euicc_certificate,
			certificate_identifiers = EXCLUDED.certificate_identifiers,
			raw_payload = EXCLUDED.raw_payload,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`, tenantString(tenantID), state.EID, eidValue, state.DefaultSMDPAddress, state.RootSMDSAddress,
		info1, info2, caps, deviceInfo, eumCert, euiccCert, encodedIdentifiers, rawPayload, createdAt, updatedAt)
	return err
}

func importOperation(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, operation dataact.OperationRecord) error {
	payload, err := dataact.DecodeOptionalBase64(operation.Payload)
	if err != nil {
		return err
	}
	createdAt, updatedAt := dataact.ImportTimestamps(operation.CreatedAt, operation.UpdatedAt)
	_, err = tx.Exec(ctx, `
		INSERT INTO operations (id, tenant_id, eid, sequence_number, kind, payload, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, eid, sequence_number)
		DO UPDATE SET id = EXCLUDED.id,
			kind = EXCLUDED.kind,
			payload = EXCLUDED.payload,
			status = EXCLUDED.status,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at
	`, operation.ID, tenantString(tenantID), operation.EID, operation.SequenceNumber, operation.Kind, payload, operation.Status, createdAt, updatedAt)
	return err
}

func importNotification(ctx context.Context, tx pgx.Tx, tenantID storage.TenantID, notification dataact.NotificationRecord) error {
	payload, err := dataact.DecodeOptionalBase64(notification.Payload)
	if err != nil {
		return err
	}
	sequenceNumber, err := dataact.NotificationSequence(notification)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO notifications (id, tenant_id, eid, sequence_number, kind, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, eid, sequence_number)
		DO UPDATE SET id = EXCLUDED.id,
			kind = EXCLUDED.kind,
			payload = EXCLUDED.payload,
			created_at = EXCLUDED.created_at
	`, notification.ID, tenantString(tenantID), notification.EID, sequenceNumber, notification.Kind, payload, notification.CreatedAt)
	return err
}

func syncImportSequences(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		SELECT setval(pg_get_serial_sequence('operations', 'id'), COALESCE((SELECT MAX(id) FROM operations), 1), true);
		SELECT setval(pg_get_serial_sequence('notifications', 'id'), COALESCE((SELECT MAX(id) FROM notifications), 1), true);
	`)
	return err
}

var _ dataact.BundleImporter = (*Store)(nil)
