//! Application authentication is independent of Mesh routing names and UDP keys.
use anyhow::{Context, ensure};
use codewire_daemon_proto::daemon::v1;
use codewire_tailnet::derp::key::{NodePrivate, NodePublic};
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) const MAX_PAYLOAD: usize = 256 * 1024;
const MAX_HELLO: usize = 2048;
const MAX_FRAME: usize = MAX_PAYLOAD + 8192;
const DOMAIN: &[u8] = b"codewire.host-member/v1\0";
const HEADER: usize = 32 + 1 + 8 + 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub environment_id: String,
    pub org: String,
    pub network: String,
    pub target_wg: [u8; 32],
    pub caller: [u8; 32],
    pub target: [u8; 32],
    pub grant_id: String,
    pub grant_revision: u64,
}

pub(super) fn canonical_uuid(value: &str) -> anyhow::Result<uuid::Uuid> {
    let id = uuid::Uuid::parse_str(value).context("expected canonical UUID")?;
    ensure!(
        !id.is_nil() && id.to_string() == value,
        "expected canonical nonnil UUID"
    );
    Ok(id)
}

impl Binding {
    pub fn validate(&self) -> anyhow::Result<()> {
        canonical_uuid(&self.environment_id)?;
        canonical_uuid(&self.grant_id)?;
        ensure!(
            self.grant_revision > 0,
            "member grant revision is unavailable"
        );
        for value in [&self.org, &self.network] {
            ensure!(
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
                "member scope is invalid"
            );
        }
        for key in [&self.target_wg, &self.caller, &self.target] {
            ensure!(
                key.iter().any(|b| *b != 0),
                "member public key is unavailable"
            );
        }
        Ok(())
    }

    pub fn scope(&self) -> v1::HostControlScope {
        v1::HostControlScope {
            environment_id: self.environment_id.clone(),
            org_id: self.org.clone(),
            network_id: self.network.clone(),
            caller_key: self.caller.to_vec(),
            target_key: self.target.to_vec(),
            grant_id: self.grant_id.clone(),
            expected_grant_revision: self.grant_revision,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    binding: Binding,
    challenge: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    binding: Binding,
    client: [u8; 32],
    server: [u8; 32],
    domain: String,
}

async fn read_frame<S: AsyncRead + Unpin>(io: &mut S, maximum: usize) -> anyhow::Result<Vec<u8>> {
    let size = io.read_u32().await? as usize;
    ensure!(size > 0 && size <= maximum, "member frame bound exceeded");
    let mut bytes = vec![0; size];
    io.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame<S: AsyncWrite + Unpin>(
    io: &mut S,
    bytes: &[u8],
    maximum: usize,
) -> anyhow::Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "member frame bound exceeded"
    );
    io.write_u32(bytes.len() as u32).await?;
    io.write_all(bytes).await?;
    io.flush().await?;
    Ok(())
}

/// All malformed/replayed frames permanently poison this connection. A new
/// connection has fresh challenges and cannot replay a previous transcript.
pub(super) struct Channel<S> {
    io: S,
    secret: NodePrivate,
    peer: NodePublic,
    transcript: [u8; 32],
    send_direction: u8,
    sent: u64,
    received: u64,
    closed: bool,
    pub binding: Binding,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Channel<S> {
    pub fn refuse(&mut self) {
        self.closed = true;
    }

    pub async fn caller(mut io: S, secret: NodePrivate, binding: Binding) -> anyhow::Result<Self> {
        binding.validate()?;
        ensure!(
            *secret.public().as_bytes() == binding.caller,
            "caller key identity changed"
        );
        let peer = NodePublic::from_raw(binding.target);
        secret.require_contributory(&peer)?;
        let mut challenge = [0; 32];
        OsRng.fill_bytes(&mut challenge);
        let hello = serde_json::to_vec(&Hello {
            binding: binding.clone(),
            challenge,
        })?;
        write_frame(&mut io, &hello, MAX_HELLO).await?;
        let sealed = read_frame(&mut io, MAX_HELLO).await?;
        let clear = secret.open_from(&peer, &sealed)?;
        let proof: Proof =
            serde_json::from_slice(&clear).context("invalid member possession proof")?;
        ensure!(
            proof.binding == binding
                && proof.client == challenge
                && proof.server != [0; 32]
                && proof.domain == "codewire.host-member/v1/server",
            "member challenge or scope changed"
        );
        let reply = serde_json::to_vec(&Proof {
            domain: "codewire.host-member/v1/caller".into(),
            ..proof
        })?;
        write_frame(
            &mut io,
            &secret.seal_to(&peer, &reply, &mut OsRng)?,
            MAX_HELLO,
        )
        .await?;
        let transcript = transcript(&hello, &clear);
        Ok(Self {
            io,
            secret,
            peer,
            transcript,
            send_direction: 1,
            sent: 0,
            received: 0,
            closed: false,
            binding,
        })
    }

    pub async fn target(
        mut io: S,
        secret: NodePrivate,
        expected: &Binding,
    ) -> anyhow::Result<Self> {
        let raw = read_frame(&mut io, MAX_HELLO).await?;
        let hello: Hello = serde_json::from_slice(&raw).context("invalid member hello")?;
        hello.binding.validate()?;
        ensure!(
            hello.challenge != [0; 32]
                && hello.binding.environment_id == expected.environment_id
                && hello.binding.org == expected.org
                && hello.binding.network == expected.network
                && hello.binding.target_wg == expected.target_wg
                && hello.binding.target == *secret.public().as_bytes(),
            "member target or routing scope changed"
        );
        let peer = NodePublic::from_raw(hello.binding.caller);
        secret.require_contributory(&peer)?;
        let mut server = [0; 32];
        OsRng.fill_bytes(&mut server);
        let proof = Proof {
            binding: hello.binding.clone(),
            client: hello.challenge,
            server,
            domain: "codewire.host-member/v1/server".into(),
        };
        let clear = serde_json::to_vec(&proof)?;
        write_frame(
            &mut io,
            &secret.seal_to(&peer, &clear, &mut OsRng)?,
            MAX_HELLO,
        )
        .await?;
        let reply = secret.open_from(&peer, &read_frame(&mut io, MAX_HELLO).await?)?;
        let reply: Proof =
            serde_json::from_slice(&reply).context("invalid caller possession proof")?;
        ensure!(
            reply.binding == proof.binding
                && reply.client == proof.client
                && reply.server == server
                && reply.domain == "codewire.host-member/v1/caller",
            "caller challenge or scope changed"
        );
        Ok(Self {
            io,
            secret,
            peer,
            transcript: transcript(&raw, &clear),
            send_direction: 2,
            sent: 0,
            received: 0,
            closed: false,
            binding: hello.binding,
        })
    }

    /// Ends the connection from the caller's side: a FIN once the target has
    /// acknowledged everything sent, then whatever the target still sends is
    /// discarded until it closes too. The target ends its connection task on
    /// that FIN, so its slot is free before this process exits.
    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.closed = true;
        self.io.shutdown().await?;
        let mut discard = [0; 256];
        while self.io.read(&mut discard).await? > 0 {}
        Ok(())
    }

    pub async fn send(&mut self, action: u8, payload: &[u8]) -> anyhow::Result<()> {
        ensure!(
            !self.closed && payload.len() <= MAX_PAYLOAD + 1 && (1..=7).contains(&action),
            "member channel or payload refused"
        );
        self.closed = true;
        let sequence = self
            .sent
            .checked_add(1)
            .context("member sequence exhausted")?;
        let mut clear = Vec::with_capacity(HEADER + payload.len());
        clear.extend_from_slice(&self.transcript);
        clear.push(self.send_direction);
        clear.extend_from_slice(&sequence.to_be_bytes());
        clear.push(action);
        clear.extend_from_slice(payload);
        let sealed = self.secret.seal_to(&self.peer, &clear, &mut OsRng)?;
        write_frame(&mut self.io, &sealed, MAX_FRAME).await?;
        self.sent = sequence;
        self.closed = false;
        Ok(())
    }

    pub async fn receive(&mut self) -> anyhow::Result<(u8, Vec<u8>)> {
        ensure!(!self.closed, "member connection was refused");
        self.closed = true;
        let sealed = read_frame(&mut self.io, MAX_FRAME).await?;
        let clear = self.secret.open_from(&self.peer, &sealed)?;
        ensure!(
            (HEADER..=HEADER + MAX_PAYLOAD + 1).contains(&clear.len()),
            "member payload bound exceeded"
        );
        let sequence = u64::from_be_bytes(clear[33..41].try_into().expect("fixed header"));
        let expected = self
            .received
            .checked_add(1)
            .context("member sequence exhausted")?;
        ensure!(
            clear[..32] == self.transcript
                && clear[32] == 3 - self.send_direction
                && sequence == expected
                && (1..=7).contains(&clear[41]),
            "member transcript/direction/sequence refused"
        );
        self.received = sequence;
        self.closed = false;
        Ok((clear[41], clear[HEADER..].to_vec()))
    }
}

fn transcript(hello: &[u8], proof: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update((hello.len() as u64).to_be_bytes());
    hash.update(hello);
    hash.update(proof);
    hash.finalize().into()
}

pub(super) fn decode<T: Message + Default>(payload: &[u8]) -> anyhow::Result<T> {
    ensure!(
        payload.len() <= MAX_PAYLOAD,
        "member payload bound exceeded"
    );
    let result = T::decode(payload).context("invalid member typed payload")?;
    ensure!(
        result.encode_to_vec() == payload,
        "member protobuf contains unknown or noncanonical fields"
    );
    Ok(result)
}

/// Responses begin with one fixed success/refusal byte; raw gRPC diagnostics,
/// owner headers and provider configuration never cross this boundary.
pub(super) fn response<T: Message>(value: anyhow::Result<T>) -> anyhow::Result<Vec<u8>> {
    match value {
        Ok(value) => {
            let bytes = value.encode_to_vec();
            ensure!(bytes.len() <= MAX_PAYLOAD, "member response bound exceeded");
            let mut result = vec![1];
            result.extend(bytes);
            Ok(result)
        }
        Err(_) => Ok(vec![0]),
    }
}
pub(super) fn result<T: Message + Default>(bytes: &[u8]) -> anyhow::Result<T> {
    ensure!(
        bytes.first() == Some(&1),
        "member request refused; retain and observe the original request UUID"
    );
    decode(&bytes[1..])
}

#[cfg(test)]
mod sequence_tests {
    use super::*;

    #[tokio::test]
    async fn member_wire_server_proof_cannot_be_reflected_as_caller_possession() {
        let caller = NodePrivate::from_raw([11; 32]);
        let target = NodePrivate::from_raw([22; 32]);
        let binding = Binding {
            environment_id: uuid::Uuid::new_v4().to_string(),
            org: "org".into(),
            network: "network".into(),
            target_wg: *target.public().as_bytes(),
            caller: *caller.public().as_bytes(),
            target: *target.public().as_bytes(),
            grant_id: uuid::Uuid::new_v4().to_string(),
            grant_revision: 1,
        };
        let (mut attack, server) = tokio::io::duplex(8192);
        let reflection = async {
            write_frame(
                &mut attack,
                &serde_json::to_vec(&Hello {
                    binding: binding.clone(),
                    challenge: [37; 32],
                })
                .unwrap(),
                MAX_HELLO,
            )
            .await
            .unwrap();
            // This attacker has no private caller key. Symmetric box key
            // agreement still makes the unchanged server ciphertext readable
            // by its sender, so the proof's direction must reject reflection.
            let proof = read_frame(&mut attack, MAX_HELLO).await.unwrap();
            write_frame(&mut attack, &proof, MAX_HELLO).await.unwrap();
        };
        let (_, result) = tokio::join!(reflection, Channel::target(server, target, &binding));
        assert!(result.is_err());
    }

    async fn pair() -> (
        Channel<tokio::io::DuplexStream>,
        Channel<tokio::io::DuplexStream>,
    ) {
        let caller = NodePrivate::from_raw([11; 32]);
        let target = NodePrivate::from_raw([22; 32]);
        let binding = Binding {
            environment_id: uuid::Uuid::new_v4().to_string(),
            org: "org".into(),
            network: "network".into(),
            target_wg: *target.public().as_bytes(),
            caller: *caller.public().as_bytes(),
            target: *target.public().as_bytes(),
            grant_id: uuid::Uuid::new_v4().to_string(),
            grant_revision: 1,
        };
        let (a, b) = tokio::io::duplex(8192);
        let (a, b) = tokio::join!(
            Channel::caller(a, caller, binding.clone()),
            Channel::target(b, target, &binding)
        );
        (a.unwrap(), b.unwrap())
    }
    #[tokio::test]
    async fn member_wire_cancelled_partial_read_and_write_cannot_be_reissued() {
        let (mut caller, _target) = pair().await;
        // The receiver stays unpolled. An oversized-for-the-duplex write
        // crosses the first-byte boundary and then loses its local future.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                caller.send(2, &vec![7; 16384])
            )
            .await
            .is_err()
        );
        assert!(caller.closed);
        assert!(caller.send(2, &[7]).await.is_err());

        let (mut caller, mut target) = pair().await;
        caller.io.write_u32(100).await.unwrap();
        caller.io.write_all(&[1, 2]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), target.receive())
                .await
                .is_err()
        );
        assert!(target.closed);
        assert!(target.receive().await.is_err());
    }

    #[tokio::test]
    async fn member_wire_replay_direction_and_exhaustion_permanently_refuse() {
        let (mut caller, mut target) = pair().await;
        caller.send(1, &[]).await.unwrap();
        target.receive().await.unwrap();
        caller.sent = 0;
        caller.send(1, &[]).await.unwrap();
        assert!(target.receive().await.is_err());
        assert!(target.receive().await.is_err());
        let (mut caller, mut target) = pair().await;
        caller.send_direction = 2;
        caller.send(1, &[]).await.unwrap();
        assert!(target.receive().await.is_err());
        let (mut caller, _target) = pair().await;
        caller.sent = u64::MAX;
        assert!(caller.send(1, &[]).await.is_err());
    }
    #[tokio::test]
    async fn member_wire_tamper_and_old_transcript_permanently_refuse() {
        let (mut caller, mut target) = pair().await;
        let mut bytes = caller
            .secret
            .seal_to(&caller.peer, b"wrong", &mut OsRng)
            .unwrap();
        bytes[30] ^= 1;
        write_frame(&mut caller.io, &bytes, MAX_FRAME)
            .await
            .unwrap();
        assert!(target.receive().await.is_err());
        let (mut caller, mut target) = pair().await;
        caller.transcript[0] ^= 1;
        caller.send(1, &[]).await.unwrap();
        assert!(target.receive().await.is_err());
    }
}
