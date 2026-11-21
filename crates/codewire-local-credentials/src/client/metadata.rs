//! A credential's status and store persistence, as the authority reports
//! them; any value it shouldn't send is data loss.

use codewire_access::CredentialStatus;
use codewire_protected_store::ProtectedStorePersistence;
use tonic::Status;

use crate::control::v1;

pub(super) fn status_from_proto(value: i32) -> Result<CredentialStatus, Status> {
    match v1::CredentialStatus::try_from(value) {
        Ok(v1::CredentialStatus::Active) => Ok(CredentialStatus::Active),
        Ok(v1::CredentialStatus::Expired) => Ok(CredentialStatus::Expired),
        Ok(v1::CredentialStatus::RefreshFailed) => Ok(CredentialStatus::RefreshFailed),
        Ok(v1::CredentialStatus::Revoked) => Ok(CredentialStatus::Revoked),
        Ok(v1::CredentialStatus::Unspecified) | Err(_) => Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        )),
    }
}

pub(super) fn persistence_from_proto(value: i32) -> Result<ProtectedStorePersistence, Status> {
    match v1::ProtectedStorePersistence::try_from(value) {
        Ok(v1::ProtectedStorePersistence::OperatingSystem) => {
            Ok(ProtectedStorePersistence::OperatingSystem)
        }
        Ok(v1::ProtectedStorePersistence::ProcessLifetime) => {
            Ok(ProtectedStorePersistence::ProcessLifetime)
        }
        Ok(v1::ProtectedStorePersistence::Unspecified) | Err(_) => Err(Status::data_loss(
            "local credential authority returned invalid metadata",
        )),
    }
}
