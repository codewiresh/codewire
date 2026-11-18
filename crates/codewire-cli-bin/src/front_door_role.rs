//! The environment's TLS front door (#3999), entered from `main` before the
//! CLI parses arguments, reads settings or resolves paths. The process
//! confines itself before it makes its CA, and nothing opened before that
//! may outlive the confinement: on macOS a home-directory lookup, for one,
//! can leave a Mach connection that Seatbelt does not take back. So it reads
//! exactly the two arguments the runner passes, in the runner's order.
use std::ffi::OsString;

pub(super) const ROLE: &str = "__native-front-door";

/// The exit status: 1 whenever the front door stops, 2 for any other
/// arguments. A stage that fails, such as a passed socket that arrives dead
/// and fails its role tag, has already sent the runner `failed <stage>`; a
/// front door whose serving ends sends no line. Serving never ends in `Ok`.
pub(super) fn run(arguments: &[OsString]) -> i32 {
    let Some((environment_id, generation)) = parse(arguments) else {
        return 2;
    };
    // One thread: the Linux syscall filter refuses thread creation.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        return 1;
    };
    match runtime.block_on(codewire_local_vmm::front_door::run_inherited_front_door(
        environment_id,
        generation,
    )) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// `--environment-id ID --generation N`, the arguments after the role.
fn parse(arguments: &[OsString]) -> Option<(&str, u64)> {
    let [id_flag, id, generation_flag, generation] = arguments else {
        return None;
    };
    if id_flag != "--environment-id" || generation_flag != "--generation" {
        return None;
    }
    Some((id.to_str()?, generation.to_str()?.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn it_takes_exactly_the_runners_two_arguments() {
        assert_eq!(
            parse(&arguments(&[
                "--environment-id",
                "abc",
                "--generation",
                "7"
            ])),
            Some(("abc", 7))
        );
        for refused in [
            &["--generation", "7", "--environment-id", "abc"][..],
            &["--environment-id", "abc"],
            &["--environment-id", "abc", "--generation", "seven"],
            &["--environment-id", "abc", "--generation", "7", "--extra"],
            &["--environment-id=abc", "--generation", "7", "x"],
        ] {
            assert_eq!(parse(&arguments(refused)), None, "{refused:?}");
        }
    }
}
