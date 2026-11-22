//! How a repository's clone failed, in words a person can act on.

/// How one repository was cloned, for a failure that names the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CloneTransport {
    /// The selected SSH key. `refused`: the server did not accept it.
    Ssh { refused: bool },
    /// The selected GitHub connection, through the managed bridge.
    GitHub,
    /// The user's HTTPS URL after GitHub refused the SSH key.
    HttpsAfterSshRefused { github: bool },
    /// No credential. `github`: a canonical GitHub source.
    Anonymous { github: bool },
}

pub(super) fn clone_failure_context(url: &str, transport: CloneTransport) -> String {
    let detail = match transport {
        CloneTransport::Ssh { refused: false } => " over SSH",
        CloneTransport::Ssh { refused: true } => {
            " over SSH: the server did not accept the SSH key in the Sandbox's credential profile"
        }
        CloneTransport::GitHub => " through the GitHub connection",
        CloneTransport::HttpsAfterSshRefused { github: true } => {
            " through the GitHub connection after GitHub did not accept the SSH key"
        }
        CloneTransport::HttpsAfterSshRefused { github: false } => {
            " over HTTPS after GitHub did not accept the SSH key; no GitHub connection is selected"
        }
        CloneTransport::Anonymous { github: true } => {
            " (no SSH key or GitHub connection is selected; a private repository needs one)"
        }
        CloneTransport::Anonymous { github: false } => "",
    };
    format!("git clone {url}{detail}")
}

/// What git's own output says a failed clone ran into (#5050). Only the
/// class leaves the classifier, never git's bytes, so nothing a remote server
/// writes reaches an error, a log row, the dashboard or `cw`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CloneFailure {
    /// The host refused, or asked for, a credential.
    NeedsCredentials,
    /// The host has no repository at that address, or hides it.
    NotFound,
    /// The host could not be resolved or reached.
    Unreachable,
    /// Anything else: the exit status is all that is said.
    Other,
}

impl std::fmt::Display for CloneFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NeedsCredentials => "needs credentials",
            Self::NotFound => "not found",
            Self::Unreachable => "unreachable",
            Self::Other => "other",
        })
    }
}

/// How much of git's stderr the classifier keeps: its last lines carry the
/// fatal reason.
const CLASSIFIER_TAIL_BYTES: usize = 4096;

/// Git's own messages, under `LC_ALL=C`, for each class. The first class
/// with a match wins. A remote server can steer which class a failure gets
/// by what it writes, but never the text: the sentence is ours, and the host
/// in it comes from the project's URL.
const NEEDS_CREDENTIALS: &[&str] = &[
    "Authentication failed",
    "could not read Username",
    "could not read Password",
    "terminal prompts disabled",
    "Permission denied (publickey",
    "The requested URL returned error: 401",
    "The requested URL returned error: 403",
];
const NOT_FOUND: &[&str] = &[
    "Repository not found",
    // Git's own line for a 404, `fatal: repository '<url>' not found`, which
    // is all a forge other than GitHub leaves.
    "fatal: repository '",
    "The requested URL returned error: 404",
    "does not appear to be a git repository",
];
const UNREACHABLE: &[&str] = &[
    "Could not resolve host",
    "Failed to connect",
    "Connection timed out",
    "Connection refused",
    "Network is unreachable",
    "Operation timed out",
];

/// Keeps the tail of one clone's stderr, zeroed when dropped.
#[derive(Default)]
pub(super) struct CloneFailureClassifier {
    tail: zeroize::Zeroizing<Vec<u8>>,
}

impl CloneFailureClassifier {
    pub(super) fn feed(&mut self, chunk: &[u8]) {
        self.tail.extend_from_slice(chunk);
        if self.tail.len() > CLASSIFIER_TAIL_BYTES {
            let excess = self.tail.len() - CLASSIFIER_TAIL_BYTES;
            self.tail.drain(..excess);
        }
    }

    pub(super) fn classify(&self) -> CloneFailure {
        let text = String::from_utf8_lossy(&self.tail);
        let any = |needles: &[&str]| needles.iter().any(|needle| text.contains(needle));
        if any(NEEDS_CREDENTIALS) {
            CloneFailure::NeedsCredentials
        } else if any(NOT_FOUND) {
            CloneFailure::NotFound
        } else if any(UNREACHABLE) {
            CloneFailure::Unreachable
        } else {
            CloneFailure::Other
        }
    }
}

/// The host a repository source names, from the project's own URL; never
/// from anything the remote said.
fn source_host(url: &str) -> Option<&str> {
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest,
        // `git@host:path`
        None => url.split_once(':')?.0,
    };
    let authority = rest.split('/').next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then_some(host)
}

/// The failure of one repository's clone: today's context, then a fixed
/// sentence for the class where git said what went wrong.
pub(super) fn clone_failure_message(
    url: &str,
    transport: CloneTransport,
    failure: CloneFailure,
) -> Option<String> {
    let host = source_host(url).unwrap_or("the repository's host");
    let sentence = match (failure, transport) {
        (CloneFailure::NeedsCredentials, CloneTransport::Anonymous { github: false }) => {
            format!(
                "{host} needs a credential that Codewire doesn't have; clone it in the terminal with your own"
            )
        }
        // A GitHub or SSH clone's context already says which credential to
        // select; the class then follows it in the error's chain.
        (CloneFailure::NeedsCredentials, _) => return None,
        (CloneFailure::NotFound, _) => {
            format!("{host} has no repository at that address, or the credential used can't see it")
        }
        (CloneFailure::Unreachable, _) => format!("{host} couldn't be reached from the Sandbox"),
        (CloneFailure::Other, _) => return None,
    };
    Some(format!(
        "{}: {sentence}",
        clone_failure_context(url, transport)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(stderr: &str) -> CloneFailure {
        let mut classifier = CloneFailureClassifier::default();
        // In two pieces, as the stream delivers it.
        let (head, tail) = stderr.split_at(stderr.len() / 2);
        classifier.feed(head.as_bytes());
        classifier.feed(tail.as_bytes());
        classifier.classify()
    }

    #[test]
    fn git_s_reasons_fall_into_their_classes() {
        for (stderr, class) in [
            (
                "fatal: could not read Username for 'https://forge.example': terminal prompts disabled\n",
                CloneFailure::NeedsCredentials,
            ),
            (
                "remote: HTTP Basic: Access denied\nfatal: Authentication failed for 'https://forge.example/r.git/'\n",
                CloneFailure::NeedsCredentials,
            ),
            (
                "git@github.com: Permission denied (publickey).\n",
                CloneFailure::NeedsCredentials,
            ),
            (
                "remote: Repository not found.\nfatal: repository 'https://github.com/o/r/' not found\n",
                CloneFailure::NotFound,
            ),
            (
                "fatal: unable to access 'https://forge.example/r.git/': The requested URL returned error: 404\n",
                CloneFailure::NotFound,
            ),
            (
                "Cloning into 'r'...\nfatal: repository 'https://forge.example/team/r.git/' not found\n",
                CloneFailure::NotFound,
            ),
            (
                "fatal: unable to access 'https://nowhere.invalid/r.git/': Could not resolve host: nowhere.invalid\n",
                CloneFailure::Unreachable,
            ),
            (
                "fatal: unable to access 'https://forge.example/r.git/': Failed to connect to forge.example port 443\n",
                CloneFailure::Unreachable,
            ),
            ("error: something git has never said\n", CloneFailure::Other),
            ("", CloneFailure::Other),
        ] {
            assert_eq!(classify(stderr), class, "{stderr}");
        }
    }

    #[test]
    fn only_the_tail_is_kept() {
        let mut classifier = CloneFailureClassifier::default();
        classifier.feed(b"fatal: Authentication failed\n");
        classifier.feed(&vec![b'x'; CLASSIFIER_TAIL_BYTES]);
        assert_eq!(classifier.tail.len(), CLASSIFIER_TAIL_BYTES);
        assert_eq!(classifier.classify(), CloneFailure::Other);
    }

    #[test]
    fn the_host_comes_from_the_project_s_own_url() {
        assert_eq!(
            source_host("https://git.example.org/team/r.git"),
            Some("git.example.org")
        );
        assert_eq!(
            source_host("https://user@forge.example:8443/r.git"),
            Some("forge.example")
        );
        assert_eq!(source_host("git@github.com:o/r.git"), Some("github.com"));
        assert_eq!(
            source_host("ssh://git@forge.example/r.git"),
            Some("forge.example")
        );
        assert_eq!(source_host(""), None);
    }

    #[test]
    fn each_class_has_its_fixed_sentence_and_no_remote_text() {
        const URL: &str = "https://git.example.org/team/private.git";
        let anonymous = CloneTransport::Anonymous { github: false };
        assert_eq!(
            clone_failure_message(URL, anonymous, CloneFailure::NeedsCredentials).unwrap(),
            "git clone https://git.example.org/team/private.git: git.example.org needs a credential \
             that Codewire doesn't have; clone it in the terminal with your own"
        );
        assert_eq!(
            clone_failure_message(URL, anonymous, CloneFailure::NotFound).unwrap(),
            "git clone https://git.example.org/team/private.git: git.example.org has no repository \
             at that address, or the credential used can't see it"
        );
        assert_eq!(
            clone_failure_message(URL, anonymous, CloneFailure::Unreachable).unwrap(),
            "git clone https://git.example.org/team/private.git: git.example.org couldn't be \
             reached from the Sandbox"
        );
        assert_eq!(
            clone_failure_message(URL, anonymous, CloneFailure::Other),
            None
        );
        // A GitHub or SSH clone keeps today's wording, which names the
        // credential to select.
        assert_eq!(
            clone_failure_message(
                "https://github.com/o/r.git",
                CloneTransport::Anonymous { github: true },
                CloneFailure::NeedsCredentials,
            ),
            None
        );

        // Whatever the remote wrote, only the class reaches the message.
        let hostile = "remote: <script>alert(1)</script> private-remote-words\nfatal: Authentication failed\n";
        let failure = classify(hostile);
        let message = clone_failure_message(URL, anonymous, failure).unwrap();
        assert!(
            !message.contains("script") && !message.contains("private-remote-words"),
            "{message}"
        );
    }
}
