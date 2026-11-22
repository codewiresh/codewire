//! The refusal of an environment name that a live environment already has.
//! A local VM's supervisor and the cloud's create refuse it in the same
//! sentence (docs/dev/CLI-PARITY.md, R1).

/// Where an environment runs, as `cw` names it in messages and flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvironmentPlacement {
    Local,
    Cloud,
}

impl EnvironmentPlacement {
    fn word(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Cloud => "cloud",
        }
    }
}

/// Why a create under `name` was refused, and the two ways on.
pub fn environment_name_taken(placement: EnvironmentPlacement, name: &str) -> String {
    let word = placement.word();
    format!(
        "{word} environment {name:?} already exists (remove it with `cw --{word} rm {name}` or choose another --name)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_placements_say_it_in_one_sentence_naming_their_own_flag() {
        assert_eq!(
            environment_name_taken(EnvironmentPlacement::Local, "app"),
            "local environment \"app\" already exists (remove it with `cw --local rm app` or choose another --name)"
        );
        assert_eq!(
            environment_name_taken(EnvironmentPlacement::Cloud, "app"),
            "cloud environment \"app\" already exists (remove it with `cw --cloud rm app` or choose another --name)"
        );
    }
}
