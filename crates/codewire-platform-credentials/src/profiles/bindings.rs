//! An environment's binding to a profile revision: create, replace, read and
//! delete, each under the fence its caller holds.

use super::*;

impl PlatformAccessProfileStore {
    /// The context must already authorize this exact environment and selection.
    /// This does not increment or invent an environment operation generation.
    /// Personal confirmation is an explicit per-call choice attributed to the
    /// authenticated creator, not identity proof from an unchecked request ID.
    /// Organization selections supply `None`; personal selections must supply
    /// the exact profile owner and remain permitted by current context policy.
    pub async fn create_binding(
        &self,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self
            .create_binding_in(&mut tx, context, binding, personal_owner_confirmation)
            .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Compose a binding write with the caller's authorization row locks in one
    /// transaction. The caller owns commit/rollback; all store fences still run.
    pub async fn create_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, &binding)?;
        lock_environment(tx, context, false, true).await?;
        self.admit_binding(tx, context, &binding, personal_owner_confirmation)
            .await?;
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(binding.environment_id.as_str())
        .bind(binding.profile_id.as_str())
        .bind(generation(binding.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(binding)
    }

    /// Admit only metadata for a newly inserted pending environment at operation
    /// generation zero. This never derives a grant or invents a future operation.
    /// The caller must authorize creator/membership and compose the new row and
    /// creator ACL in this same transaction. Runtime APIs still require a
    /// positive, admitted operation generation and a running environment.
    pub async fn create_pending_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        binding: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, &binding)?;
        if context.environment_generation != 0 || context.placement != GrantPlacement::Platform {
            return Err(Error::InvalidInput);
        }
        let organization = context
            .organization_id
            .as_ref()
            .ok_or(Error::InvalidInput)?;
        lock_owner(tx, &Owner::User(context.user_id.clone())).await?;
        lock_owner(tx, &Owner::Organization(organization.clone())).await?;
        let pending: Option<bool> = sqlx::query_scalar(
            "SELECT environment_operation_generation=0 AND state='pending' AND desired_state='started' \
             AND deletion_requested_at IS NULL AND type='sandbox' FROM environments \
             WHERE id=$1 AND created_by=$2 AND org_id=$3 FOR UPDATE",
        )
        .bind(context.environment_id.as_str())
        .bind(context.user_id.as_str())
        .bind(organization.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database_error)?;
        match pending {
            None => return Err(Error::NotFound),
            Some(false) => return Err(Error::StaleEnvironment),
            Some(true) => {}
        }
        let profile = profile_for_context(tx, context, &binding).await?;
        validate_personal_confirmation(context, &profile, personal_owner_confirmation)?;
        let credentials = load_credentials(tx, &profile).await?;
        validate_profile_entries(&profile, &credentials, &self.catalog).map_err(access_error)?;
        // A credential that needs Reconnect does not block the Sandbox: like a
        // missing GitHub connection, only its capability is unavailable until
        // the owner reconnects it. Runtime admission withholds it per slot.
        for credential in credentials.values() {
            if !context.authorized_credentials.contains(&credential.id) {
                return Err(Error::UnsupportedEntry);
            }
        }
        sqlx::query(
            "INSERT INTO platform_environment_access_bindings \
             (environment_id,profile_id,profile_revision,personal_owner_confirmed_by) \
             VALUES ($1,$2,$3,$4)",
        )
        .bind(binding.environment_id.as_str())
        .bind(binding.profile_id.as_str())
        .bind(generation(binding.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(binding)
    }

    /// Rebinding never inherits prior consent, including rebinding the same
    /// immutable revision. The caller must explicitly confirm it again.
    pub async fn replace_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
        replacement: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self
            .replace_binding_in(
                &mut tx,
                context,
                expected,
                replacement,
                personal_owner_confirmation,
            )
            .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Transaction-composable exact CAS, retaining every revision/owner fence.
    pub async fn replace_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
        replacement: EnvironmentAccessBinding,
        personal_owner_confirmation: Option<&OwnerId>,
    ) -> Result<EnvironmentAccessBinding, Error> {
        validate_binding(context, expected)?;
        validate_binding(context, &replacement)?;
        lock_environment(tx, context, false, true).await?;
        if load_binding(tx, context).await?.binding != *expected {
            return Err(Error::StaleBinding);
        }
        self.admit_binding(tx, context, &replacement, personal_owner_confirmation)
            .await?;
        sqlx::query(
            "UPDATE platform_environment_access_bindings SET profile_id=$2,profile_revision=$3, \
             personal_owner_confirmed_by=$4,updated_at=now() WHERE environment_id=$1",
        )
        .bind(replacement.environment_id.as_str())
        .bind(replacement.profile_id.as_str())
        .bind(generation(replacement.profile_revision)?)
        .bind(personal_owner_confirmation.map(OwnerId::as_str))
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
        Ok(replacement)
    }

    pub async fn get_binding(
        &self,
        context: &GrantContext,
    ) -> Result<EnvironmentAccessBinding, Error> {
        Ok(self.get_binding_metadata(context).await?.binding)
    }

    /// Atomically inspect exact binding metadata, including missing consent.
    /// Neither this result nor an enrollment/membership decision grants use.
    pub async fn get_binding_metadata(
        &self,
        context: &GrantContext,
    ) -> Result<PlatformBindingMetadata, Error> {
        let mut tx = self.begin_transaction().await?;
        let binding = self.get_binding_metadata_in(&mut tx, context).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(binding)
    }

    /// Compose a metadata-only read with the caller's current authority locks.
    pub async fn get_binding_metadata_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
    ) -> Result<PlatformBindingMetadata, Error> {
        lock_environment(tx, context, false, false).await?;
        let binding = load_binding(tx, context).await?;
        profile_for_context(tx, context, &binding.binding).await?;
        Ok(binding)
    }

    /// `get_binding_metadata`, then `get_revision(owner, bound profile, bound
    /// revision)`, in one transaction: the two profile reads of runtime
    /// authority. The outer error is the binding read's. The inner result is
    /// the revision read's, which a caller consults only after it has compared
    /// the binding with its own scope, as when the reads were separate.
    ///
    /// `owner` must be the context's user or organization. Both are already
    /// locked by the binding read, so the revision read takes no new lock: it
    /// re-locks rows this transaction holds and reads the same immutable
    /// revision, which is the separate reads when nothing commits between them.
    ///
    /// Runtime authority calls this on every resolve, so it uses the merged
    /// statements `ENVIRONMENT_FENCE` and `BOUND_PROFILE`, whose residual
    /// differences from the separate statements are documented there. Every
    /// other caller keeps `get_binding_metadata` and `get_revision`.
    pub async fn get_binding_metadata_and_revision(
        &self,
        context: &GrantContext,
        owner: &Owner,
    ) -> Result<(PlatformBindingMetadata, Result<AccessProfile, Error>), Error> {
        let context_owner = match owner {
            Owner::User(id) => *id == context.user_id,
            Owner::Organization(id) => context.organization_id.as_ref() == Some(id),
        };
        if !context_owner {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.begin_transaction().await?;
        lock_runtime_environment(&mut tx, context, false).await?;
        let bound = load_bound_profile(&mut tx, context, Some(owner))
            .await?
            .ok_or(Error::NotFound)?;
        tx.commit().await.map_err(database_error)?;
        let revision = bound.owner_revision.ok_or(Error::InvalidInput)?;
        Ok((bound.binding, revision))
    }

    pub async fn delete_binding(
        &self,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
    ) -> Result<(), Error> {
        let mut tx = self.begin_transaction().await?;
        self.delete_binding_in(&mut tx, context, expected).await?;
        tx.commit().await.map_err(database_error)
    }

    /// Compose clearing an exact binding with the caller's authorization locks.
    pub async fn delete_binding_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        context: &GrantContext,
        expected: &EnvironmentAccessBinding,
    ) -> Result<(), Error> {
        validate_binding(context, expected)?;
        lock_environment(tx, context, false, true).await?;
        if load_binding(tx, context).await?.binding != *expected {
            return Err(Error::StaleBinding);
        }
        profile_for_context(tx, context, expected).await?;
        sqlx::query("DELETE FROM platform_environment_access_bindings WHERE environment_id=$1")
            .bind(context.environment_id.as_str())
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        Ok(())
    }
}
