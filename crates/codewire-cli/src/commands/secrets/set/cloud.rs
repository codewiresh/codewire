//! The cloud's keys for a set: personal, organization and project.

use codewire_access::BindingWrite;
use zeroize::Zeroizing;

use super::KeyStore;
use crate::secret_client::{SecretClient, SecretMetadata};

pub(in crate::commands) struct CloudKeys<'a> {
    client: &'a SecretClient,
    scope: Scope<'a>,
}

enum Scope<'a> {
    User,
    Organization {
        org_id: &'a str,
    },
    Project {
        org_id: &'a str,
        id: &'a str,
        name: &'a str,
    },
}

impl<'a> CloudKeys<'a> {
    pub(in crate::commands) fn user(client: &'a SecretClient) -> Self {
        Self {
            client,
            scope: Scope::User,
        }
    }

    pub(in crate::commands) fn organization(client: &'a SecretClient, org_id: &'a str) -> Self {
        Self {
            client,
            scope: Scope::Organization { org_id },
        }
    }

    pub(in crate::commands) fn project(
        client: &'a SecretClient,
        org_id: &'a str,
        id: &'a str,
        name: &'a str,
    ) -> Self {
        Self {
            client,
            scope: Scope::Project { org_id, id, name },
        }
    }
}

impl KeyStore for CloudKeys<'_> {
    fn command(&self) -> String {
        match &self.scope {
            Scope::User => "cw secrets --cloud --user".to_owned(),
            Scope::Organization { .. } => "cw secrets --cloud --organization".to_owned(),
            Scope::Project { name, .. } => format!("cw secrets --cloud --project={name}"),
        }
    }

    fn place(&self) -> String {
        match &self.scope {
            Scope::User => String::new(),
            Scope::Organization { .. } => " in your organization".to_owned(),
            Scope::Project { name, .. } => format!(" in project {name}"),
        }
    }

    fn plain_set_line(&self, key: &str) -> String {
        match &self.scope {
            Scope::User | Scope::Organization { .. } => format!("Secret {key} set."),
            Scope::Project { name, .. } => format!("Secret {key} set in project {name:?}."),
        }
    }

    async fn find(&mut self, key: &str) -> anyhow::Result<Option<SecretMetadata>> {
        let secrets = match &self.scope {
            Scope::User => self.client.list_user_secrets().await?,
            Scope::Organization { org_id } => self.client.list_org_secrets(org_id).await?,
            Scope::Project { org_id, id, .. } => {
                self.client.list_project_secrets(org_id, id).await?
            }
        };
        Ok(secrets.into_iter().find(|secret| secret.key == key))
    }

    async fn require_bindings(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn write(
        &mut self,
        key: &str,
        value: Option<Zeroizing<Vec<u8>>>,
        binding: &BindingWrite,
    ) -> anyhow::Result<Option<SecretMetadata>> {
        let value = match value {
            Some(mut bytes) => match String::from_utf8(std::mem::take(&mut *bytes)) {
                Ok(value) => Zeroizing::new(value),
                Err(error) => {
                    let _bytes = Zeroizing::new(error.into_bytes());
                    anyhow::bail!("workload-secret value must be valid UTF-8")
                }
            },
            // An empty value is the wire's "no value".
            None => Zeroizing::new(String::new()),
        };
        let client = self.client;
        let (written, context) = match &self.scope {
            Scope::User => (
                client.write_user_secret(key, &value, binding).await,
                "set user secret",
            ),
            Scope::Organization { org_id } => (
                client.write_org_secret(org_id, key, &value, binding).await,
                "set org secret",
            ),
            Scope::Project { org_id, id, .. } => (
                client
                    .write_project_secret(org_id, id, key, &value, binding)
                    .await,
                "set secret",
            ),
        };
        written.map_err(|error| error.context(context))?;
        Ok(None)
    }
}
