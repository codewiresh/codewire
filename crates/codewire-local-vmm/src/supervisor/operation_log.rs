//! The supervisor log's lines about lifecycle operations themselves.

use super::*;

impl SupervisorCore {
    /// Logs that this supervisor picked up an operation another left
    /// unfinished, such as one that exited during a create's image pull
    /// (#4418): the operation, its kind and the effect it resumes at. A
    /// person whose `cw` lost contact can then see it carried on.
    pub(super) fn log_operation_resumed(&self, operation: &OperationRecord) {
        let Some(log) = self.log.as_ref() else {
            return;
        };
        let effect = supervisor_effect(operation.kind, operation.checkpoint)
            .ok()
            .flatten()
            .map_or("none", LifecycleEffect::name);
        let mut fields = vec![
            ("kind", LogField::Name(operation.kind.as_str())),
            ("operation", LogField::Id(operation.operation_id)),
            ("effect", LogField::Name(effect)),
        ];
        if let Some(environment_id) = operation.environment_id {
            fields.push(("environment", LogField::Id(environment_id)));
        }
        log.record("operation_resumed", &fields);
    }
}
