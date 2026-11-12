use super::*;

#[test]
fn a_start_does_not_ask_an_authority_older_than_the_github_question() {
    assert_eq!(platform_github_askable(15), Err("authority_older"));
    assert_eq!(platform_github_askable(16), Ok(()));
}
