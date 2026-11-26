//! Finite `v3:` hexadecimal bitset tables for [`super::ManagedCredentialClients`]
//! selections carrying `Gemini` (`0x80`) and/or `Antigravity` (`0x100`) (#6555).
//! Every earlier `v1:` and `v2:` token keeps its exact bytes.

pub(super) const V3_GEMINI_ENCODINGS: [&str; 32] = [
    "v3:80", "v3:81", "v3:82", "v3:83", "v3:84", "v3:85", "v3:86", "v3:87", "v3:88", "v3:89",
    "v3:8a", "v3:8b", "v3:8c", "v3:8d", "v3:8e", "v3:8f", "v3:90", "v3:91", "v3:92", "v3:93",
    "v3:94", "v3:95", "v3:96", "v3:97", "v3:98", "v3:99", "v3:9a", "v3:9b", "v3:9c", "v3:9d",
    "v3:9e", "v3:9f",
];

pub(super) const V3_GEMINI_ANTHROPIC_SUBSCRIPTION_ENCODINGS: [&str; 16] = [
    "v3:a4", "v3:a5", "v3:a6", "v3:a7", "v3:ac", "v3:ad", "v3:ae", "v3:af", "v3:b4", "v3:b5",
    "v3:b6", "v3:b7", "v3:bc", "v3:bd", "v3:be", "v3:bf",
];

pub(super) const V3_GEMINI_ANTHROPIC_SIGN_IN_ENCODINGS: [&str; 16] = [
    "v3:c4", "v3:c5", "v3:c6", "v3:c7", "v3:cc", "v3:cd", "v3:ce", "v3:cf", "v3:d4", "v3:d5",
    "v3:d6", "v3:d7", "v3:dc", "v3:dd", "v3:de", "v3:df",
];

pub(super) const V3_ANTIGRAVITY_ENCODINGS: [&str; 32] = [
    "v3:100", "v3:101", "v3:102", "v3:103", "v3:104", "v3:105", "v3:106", "v3:107", "v3:108",
    "v3:109", "v3:10a", "v3:10b", "v3:10c", "v3:10d", "v3:10e", "v3:10f", "v3:110", "v3:111",
    "v3:112", "v3:113", "v3:114", "v3:115", "v3:116", "v3:117", "v3:118", "v3:119", "v3:11a",
    "v3:11b", "v3:11c", "v3:11d", "v3:11e", "v3:11f",
];

pub(super) const V3_ANTIGRAVITY_ANTHROPIC_SUBSCRIPTION_ENCODINGS: [&str; 16] = [
    "v3:124", "v3:125", "v3:126", "v3:127", "v3:12c", "v3:12d", "v3:12e", "v3:12f", "v3:134",
    "v3:135", "v3:136", "v3:137", "v3:13c", "v3:13d", "v3:13e", "v3:13f",
];

pub(super) const V3_ANTIGRAVITY_ANTHROPIC_SIGN_IN_ENCODINGS: [&str; 16] = [
    "v3:144", "v3:145", "v3:146", "v3:147", "v3:14c", "v3:14d", "v3:14e", "v3:14f", "v3:154",
    "v3:155", "v3:156", "v3:157", "v3:15c", "v3:15d", "v3:15e", "v3:15f",
];

pub(super) const V3_GEMINI_ANTIGRAVITY_ENCODINGS: [&str; 32] = [
    "v3:180", "v3:181", "v3:182", "v3:183", "v3:184", "v3:185", "v3:186", "v3:187", "v3:188",
    "v3:189", "v3:18a", "v3:18b", "v3:18c", "v3:18d", "v3:18e", "v3:18f", "v3:190", "v3:191",
    "v3:192", "v3:193", "v3:194", "v3:195", "v3:196", "v3:197", "v3:198", "v3:199", "v3:19a",
    "v3:19b", "v3:19c", "v3:19d", "v3:19e", "v3:19f",
];

pub(super) const V3_GEMINI_ANTIGRAVITY_ANTHROPIC_SUBSCRIPTION_ENCODINGS: [&str; 16] = [
    "v3:1a4", "v3:1a5", "v3:1a6", "v3:1a7", "v3:1ac", "v3:1ad", "v3:1ae", "v3:1af", "v3:1b4",
    "v3:1b5", "v3:1b6", "v3:1b7", "v3:1bc", "v3:1bd", "v3:1be", "v3:1bf",
];

pub(super) const V3_GEMINI_ANTIGRAVITY_ANTHROPIC_SIGN_IN_ENCODINGS: [&str; 16] = [
    "v3:1c4", "v3:1c5", "v3:1c6", "v3:1c7", "v3:1cc", "v3:1cd", "v3:1ce", "v3:1cf", "v3:1d4",
    "v3:1d5", "v3:1d6", "v3:1d7", "v3:1dc", "v3:1dd", "v3:1de", "v3:1df",
];
