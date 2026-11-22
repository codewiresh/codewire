//! `cw desktop`'s command line and what it makes of a desktop answer.

use buffa_types::Timestamp;
use clap::Parser as _;
use codewire_proto::codewire::v1::{
    EnvironmentDesktop, EnvironmentDesktopRunning, EnvironmentDesktopState,
};

use super::state::{Desktop, InvalidAnswer, ViewerPassword};
use crate::{Cli, Command};

fn parsed(line: &[&str]) -> Result<super::DesktopArgs, clap::Error> {
    match Cli::try_parse_from(line)?.command {
        Command::Desktop(args) => Ok(args),
        _ => panic!("not the desktop command"),
    }
}

fn in_state(state: EnvironmentDesktopState) -> EnvironmentDesktop {
    EnvironmentDesktop {
        state: state.into(),
        ..Default::default()
    }
}

fn running(password: &str) -> EnvironmentDesktop {
    EnvironmentDesktop {
        state: EnvironmentDesktopState::Running.into(),
        running: Some(EnvironmentDesktopRunning {
            display: ":1".into(),
            port: 5901,
            started_at: Some(Timestamp::from_unix(1_795_000_000, 0)).into(),
            viewer_password: password.into(),
            ..Default::default()
        })
        .into(),
        ..Default::default()
    }
}

#[test]
fn the_environment_is_named_once_and_the_modes_exclude_each_other() {
    let positional = parsed(&["cw", "desktop", "app"]).expect("ENV");
    assert_eq!(positional.environment.as_deref(), Some("app"));
    assert!(!positional.no_open && !positional.status && !positional.stop);
    let flag = parsed(&["cw", "desktop", "--in", "app", "--no-open"]).expect("--in ENV");
    assert_eq!(flag.in_environment.as_deref(), Some("app"));
    assert!(flag.no_open);
    assert!(
        parsed(&["cw", "desktop"])
            .expect("the selected environment")
            .environment
            .is_none()
    );

    for together in [
        ["--status", "--stop"],
        ["--status", "--no-open"],
        ["--stop", "--no-open"],
    ] {
        let line = [&["cw", "desktop", "app"][..], &together[..]].concat();
        assert!(parsed(&line).is_err(), "{together:?}");
    }
}

#[test]
fn each_state_is_read_and_a_running_desktop_keeps_its_password_out_of_debug() {
    for (state, expected) in [
        (EnvironmentDesktopState::Unavailable, Desktop::Unavailable),
        (EnvironmentDesktopState::Stopped, Desktop::Stopped),
        (EnvironmentDesktopState::Starting, Desktop::Starting),
    ] {
        assert_eq!(Desktop::parse(in_state(state)), Ok(expected));
    }
    let Ok(Desktop::Running(desktop)) = Desktop::parse(running("a1b2c3d4")) else {
        panic!("a running desktop");
    };
    assert_eq!(desktop.password.reveal(), "a1b2c3d4");
    assert_eq!(
        desktop.started_at.map(|at| at.timestamp()),
        Some(1_795_000_000)
    );
    assert!(!format!("{desktop:?}").contains("a1b2c3d4"));
}

#[test]
fn an_answer_in_any_other_shape_is_refused_whole() {
    let mut other_display = running("a1b2c3d4");
    let mut other_port = running("a1b2c3d4");
    let mut bad_time = running("a1b2c3d4");
    if let Some(details) = other_display.running.as_option_mut() {
        details.display = ":0".into();
    }
    if let Some(details) = other_port.running.as_option_mut() {
        details.port = 5900;
    }
    if let Some(details) = bad_time.running.as_option_mut() {
        details.started_at = Some(Timestamp {
            seconds: 1_795_000_000,
            nanos: -1,
            ..Default::default()
        })
        .into();
    }
    let mut stopped_with_details = running("a1b2c3d4");
    stopped_with_details.state = EnvironmentDesktopState::Stopped.into();
    for answer in [
        in_state(EnvironmentDesktopState::Unspecified),
        in_state(EnvironmentDesktopState::Running),
        running("A1B2C3D4"),
        running("a1b2c3d4\"\ndo shell script \"id\""),
        running(""),
        other_display,
        other_port,
        bad_time,
        stopped_with_details,
    ] {
        assert_eq!(Desktop::parse(answer), Err(InvalidAnswer));
    }
}

#[test]
fn a_desktop_started_again_is_not_the_one_that_was_held() {
    let Ok(Desktop::Running(held)) = Desktop::parse(running("a1b2c3d4")) else {
        panic!("a running desktop");
    };
    let again = Desktop::parse(running("a1b2c3d4")).expect("the same desktop");
    assert!(again.is_still(&held));
    let restarted = Desktop::parse(running("z9y8x7w6")).expect("a new desktop");
    assert!(!restarted.is_still(&held));
    assert!(!Desktop::Stopped.is_still(&held));
    assert!(ViewerPassword::parse("a1b2c3d").is_none());
}

#[test]
fn the_password_is_printed_when_asked_for_and_otherwise_only_to_a_terminal() {
    use super::viewer::Opened;

    for terminal in [true, false] {
        assert!(super::prints_password(None, terminal));
        assert!(!super::prints_password(
            Some(Opened::WithPassword),
            terminal
        ));
    }
    for opened in [Opened::AskingForPassword, Opened::NoViewer] {
        assert!(super::prints_password(Some(opened), true), "{opened:?}");
        assert!(!super::prints_password(Some(opened), false), "{opened:?}");
    }
}
