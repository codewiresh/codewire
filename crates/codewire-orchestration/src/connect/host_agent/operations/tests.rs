use super::*;

const ENVIRONMENT: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
const LOCAL: &str = "9b2e7c1a-0d4f-4e8b-a6c3-5f1d2e3a4b5c";

fn reported(state: ProtoState) -> ProtoObservation {
    ProtoObservation {
        environment_id: ENVIRONMENT.into(),
        local_environment_id: LOCAL.into(),
        generation: 3,
        state: state.into(),
        vcpus: 2,
        memory_mib: 4096,
        disk_bytes: 20 << 30,
        ..Default::default()
    }
}

fn refused(observation: ProtoObservation) -> bool {
    parse_observation(observation).is_err()
}

#[test]
fn a_report_is_stored_as_the_host_states_it() {
    let running = parse_observation(reported(ProtoState::HOST_ENVIRONMENT_STATE_RUNNING)).unwrap();
    assert_eq!(running.environment_id, ENVIRONMENT);
    assert_eq!(running.local_environment_id.to_string(), LOCAL);
    assert_eq!(running.generation, 3);
    assert_eq!(running.state, HostEnvironmentState::Running);
    assert_eq!(running.vcpus, 2);
    assert_eq!(running.memory_mib, 4096);
    assert_eq!(running.disk_bytes, 20 << 30);
    assert_eq!(running.error_code, None);
    assert_eq!(running.ssh_host_key, None);

    let mut failed = reported(ProtoState::HOST_ENVIRONMENT_STATE_ERROR);
    failed.error_code = "disk_full".into();
    let failed = parse_observation(failed).unwrap();
    assert_eq!(failed.state, HostEnvironmentState::Error);
    assert_eq!(failed.error_code.as_deref(), Some("disk_full"));

    let absent = parse_observation(reported(ProtoState::HOST_ENVIRONMENT_STATE_ABSENT)).unwrap();
    assert_eq!(absent.state, HostEnvironmentState::Absent);
}

#[test]
fn a_malformed_report_is_refused() {
    assert!(refused(reported(
        ProtoState::HOST_ENVIRONMENT_STATE_UNSPECIFIED
    )));
    let mut no_local = reported(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED);
    no_local.local_environment_id.clear();
    assert!(refused(no_local));
    let mut not_an_id = reported(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED);
    not_an_id.environment_id = "dev".into();
    assert!(refused(not_an_id));
    // A generation the database cannot hold.
    let mut huge = reported(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED);
    huge.generation = u64::MAX;
    assert!(refused(huge));
    // Sizes and an error code the database cannot hold.
    let mut vcpus = reported(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED);
    vcpus.vcpus = u32::MAX;
    assert!(refused(vcpus));
    let mut disk = reported(ProtoState::HOST_ENVIRONMENT_STATE_STOPPED);
    disk.disk_bytes = u64::MAX;
    assert!(refused(disk));
    let mut code = reported(ProtoState::HOST_ENVIRONMENT_STATE_ERROR);
    code.error_code = "x".repeat(MAX_ERROR_CODE_BYTES + 1);
    assert!(refused(code));
}

#[test]
fn a_reason_is_cut_on_a_character_boundary() {
    let reason = bounded(&"é".repeat(MAX_REASON_BYTES));
    assert!(reason.len() <= MAX_REASON_BYTES);
    assert!(reason.chars().all(|character| character == 'é'));
}
