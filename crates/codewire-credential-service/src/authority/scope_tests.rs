//! A scope's personal confirmation (#5688): a sign-in's or a user token's,
//! exactly one, naming the creator; only a sign-in's admits direct delivery.

use super::*;

const CREATOR: &str = "synthetic-creator";

fn confirmed(sign_in: Option<&str>, user_token: Option<&str>) -> Scope {
    Scope {
        confirmed_by: sign_in.map(Into::into),
        confirmed_by_user_token: user_token.map(Into::into),
        ..crate::tests::scope()
    }
}

#[test]
fn a_sign_in_confirmation_admits_direct_delivery_and_a_user_tokens_does_not() {
    let sign_in = confirmed(Some(CREATOR), None);
    assert!(sign_in.context().unwrap().allow_personal_credentials);
    assert!(sign_in.direct_delivery());
    assert!(matches!(sign_in.owner(), Ok(Owner::User(owner)) if owner.as_str() == CREATOR));

    let user_token = confirmed(None, Some(CREATOR));
    assert!(user_token.context().unwrap().allow_personal_credentials);
    assert!(!user_token.direct_delivery());
    assert!(matches!(user_token.owner(), Ok(Owner::User(owner)) if owner.as_str() == CREATOR));
    assert_eq!(
        user_token.confirmation().unwrap(),
        PersonalConfirmation::UserToken(OwnerId::parse(CREATOR).unwrap())
    );
}

#[test]
fn both_confirmations_another_users_or_none_admit_nothing_personal() {
    for (sign_in, user_token) in [
        (Some(CREATOR), Some(CREATOR)),
        (None, Some("synthetic-other")),
        (Some("synthetic-other"), None),
        (None, None),
    ] {
        let scope = confirmed(sign_in, user_token);
        assert!(
            !scope.context().unwrap().allow_personal_credentials,
            "{sign_in:?} {user_token:?}"
        );
        assert!(!scope.direct_delivery(), "{sign_in:?} {user_token:?}");
        assert!(
            matches!(scope.owner(), Err(Error::Denied)),
            "{sign_in:?} {user_token:?}"
        );
    }
    assert!(matches!(
        confirmed(Some(CREATOR), Some(CREATOR)).confirmation(),
        Err(Error::Denied)
    ));
}

#[test]
fn an_organization_profile_with_any_confirmation_is_denied() {
    let organization = |sign_in: Option<&str>, user_token: Option<&str>| Scope {
        profile_user: None,
        profile_organization: Some("synthetic-org".into()),
        ..confirmed(sign_in, user_token)
    };
    assert!(matches!(
        organization(None, None).owner(),
        Ok(Owner::Organization(org)) if org.as_str() == "synthetic-org"
    ));
    for (sign_in, user_token) in [(Some(CREATOR), None), (None, Some(CREATOR))] {
        let scope = organization(sign_in, user_token);
        assert!(
            matches!(scope.owner(), Err(Error::Denied)),
            "{sign_in:?} {user_token:?}"
        );
        assert!(!scope.direct_delivery(), "{sign_in:?} {user_token:?}");
    }
}
