//! The local store's keys for a set: personal and project.

use codewire_access::BindingWrite;
use codewire_local_credentials::{AuthorityFeature, LocalCredentialClient};
use codewire_protected_store::ProtectedValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::KeyStore;
use crate::secret_client::SecretMetadata;

pub(in crate::commands) struct LocalKeys<'a> {
    client: &'a mut LocalCredentialClient,
    project: Option<(Uuid, &'a str)>,
}

impl<'a> LocalKeys<'a> {
    pub(in crate::commands) fn user(client: &'a mut LocalCredentialClient) -> Self {
        Self {
            client,
            project: None,
        }
    }

    pub(in crate::commands) fn project(
        client: &'a mut LocalCredentialClient,
        id: Uuid,
        name: &'a str,
    ) -> Self {
        Self {
            client,
            project: Some((id, name)),
        }
    }
}

impl KeyStore for LocalKeys<'_> {
    fn command(&self) -> String {
        match self.project {
            None => "cw secrets --local --user".to_owned(),
            Some((_, name)) => format!("cw secrets --local --project={name}"),
        }
    }

    fn place(&self) -> String {
        match self.project {
            None => String::new(),
            Some((_, name)) => format!(" in project {name}"),
        }
    }

    fn plain_set_line(&self, key: &str) -> String {
        match self.project {
            None => format!("Local user secret {key} set."),
            Some((_, name)) => format!("Local secret {key} set in project {name:?}."),
        }
    }

    async fn find(&mut self, key: &str) -> anyhow::Result<Option<SecretMetadata>> {
        let secrets = match self.project {
            None => self.client.list_user_workload_secrets().await?,
            Some((id, _)) => self.client.list_project_workload_secrets(id).await?,
        };
        Ok(secrets
            .iter()
            .find(|secret| secret.key == key)
            .map(super::super::local_metadata))
    }

    async fn require_bindings(&mut self) -> anyhow::Result<()> {
        let feature = AuthorityFeature::SecretBindings;
        if !feature.served_by(self.client.info().protocol_version) {
            *self.client = crate::commands::connect_local_credential_authority_serving(
                feature,
                "keep a secret's hosts",
            )
            .await?;
        }
        Ok(())
    }

    async fn write(
        &mut self,
        key: &str,
        value: Option<Zeroizing<Vec<u8>>>,
        binding: &BindingWrite,
    ) -> anyhow::Result<Option<SecretMetadata>> {
        let value = value
            .map(|mut bytes| ProtectedValue::new(std::mem::take(&mut *bytes)))
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid workload-secret value"))?;
        let key = key.to_owned();
        let (written, context) = match self.project {
            None => (
                self.client
                    .write_user_workload_secret(key, value, binding)
                    .await,
                "set local user secret",
            ),
            Some((id, _)) => (
                self.client
                    .write_project_workload_secret(id, key, value, binding)
                    .await,
                "set local project secret",
            ),
        };
        let written = written.map_err(|status| anyhow::Error::new(status).context(context))?;
        Ok(Some(super::super::local_metadata(&written)))
    }
}
