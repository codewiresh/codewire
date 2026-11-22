//! docs/dev/CLI-PARITY.md, S4: a new project's name is checked once, before
//! either store, in the grammar both stores keep.

use super::*;

#[test]
fn a_new_project_name_is_refused_before_either_store_in_one_sentence() {
    assert_eq!(
        parse_secret_project_name("web-2.prod"),
        Ok("web-2.prod".to_owned())
    );
    for refused in ["bad name", "-web", "café"] {
        assert_eq!(
            parse_secret_project_name(refused),
            Err("a secret project name starts with a letter or digit and has only letters, digits, '-', '_' and '.', at most 64 characters".to_owned()),
            "{refused:?}"
        );
    }
    assert_eq!(
        parse_secret_project_name("local:web"),
        Err("project creation requires a bare project name".to_owned())
    );
}
