#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use codewire_local_vmm::network_worker::{
    NETWORK_BOOTSTRAP_FD, NetworkWorkerStartupFailure, WORKER_PREPARED_MESSAGE,
    WORKER_READY_MESSAGE, WORKER_STATUS_MAX_BYTES, encode_worker_bootstrap,
};
use codewire_vmm_guest_probe::{
    NETWORK_HOST_HELLO_LEN, NETWORK_HOST_READY_LEN, NetworkGuestAck, NetworkHostHello,
    NetworkHostReady, NetworkKey,
};
use uuid::Uuid;

const NETWORK_DESCRIPTOR_MARKER: u8 = b'N';
const CONTROL_BYTES: usize = 64;

#[repr(C)]
union ControlBuffer {
    alignment: libc::cmsghdr,
    bytes: [u8; CONTROL_BYTES],
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn confined_product_worker_completes_the_two_phase_authenticated_bootstrap() {
    let directory = tempfile::tempdir().unwrap();
    let (mut bootstrap_parent, bootstrap_child) = std::os::unix::net::UnixStream::pair().unwrap();
    bootstrap_parent
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    bootstrap_parent
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let vm_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let generation = 9_u64;
    let token = "worker-process-test-token-0123456789abcdef";
    let key = NetworkKey::derive(token, vm_id, generation).unwrap();
    let bootstrap = encode_worker_bootstrap(vm_id, generation, &key).unwrap();
    let source = bootstrap_child.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_codewire-local-vmm-smoke"));
    command
        .arg("__native-network-worker")
        .arg("--environment-id")
        .arg(vm_id.to_string())
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this child hook uses only async-signal-safe descriptor syscalls
    // and returns before the worker executable observes process state.
    unsafe {
        command.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if source != NETWORK_BOOTSTRAP_FD && libc::dup2(source, NETWORK_BOOTSTRAP_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(NETWORK_BOOTSTRAP_FD, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let mut child = ChildGuard(child);
    drop(bootstrap_child);

    bootstrap_parent.write_all(bootstrap.as_ref()).unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap_parent),
        WORKER_PREPARED_MESSAGE
    );

    let (mut guest, worker_network) = std::os::unix::net::UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    guest
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    send_descriptor(bootstrap_parent.as_raw_fd(), worker_network.as_raw_fd());
    drop(worker_network);

    let mut hello = [0_u8; NETWORK_HOST_HELLO_LEN];
    if let Err(error) = guest.read_exact(&mut hello) {
        let status_frame = read_status_frame_result(&mut bootstrap_parent);
        let exit = child.0.wait().unwrap();
        panic!(
            "worker closed before hello: {error}; status={status_frame:?}; exit={:?}",
            exit.code()
        );
    }
    let hello = NetworkHostHello::decode(&hello, &key, vm_id, generation).unwrap();
    guest
        .write_all(&NetworkGuestAck::new(hello.nonce).unwrap().encode(&key))
        .unwrap();
    let mut ready = [0_u8; NETWORK_HOST_READY_LEN];
    guest.read_exact(&mut ready).unwrap();
    NetworkHostReady::decode(&ready, &key, &hello.nonce).unwrap();
    assert_eq!(
        read_status_frame(&mut bootstrap_parent),
        WORKER_READY_MESSAGE
    );
    let descriptors = std::fs::read_dir(format!("/proc/{}/fd", child.0.id()))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (entry.file_name(), std::fs::read_link(entry.path()).unwrap())
        })
        .collect::<Vec<_>>();
    let sockets = descriptors
        .iter()
        .filter(|(_, target)| target.to_string_lossy().starts_with("socket:"))
        .collect::<Vec<_>>();
    let mut socket_inodes = BTreeMap::<u64, usize>::new();
    for (_, target) in &sockets {
        let target = target.to_string_lossy();
        let inode = target
            .strip_prefix("socket:[")
            .and_then(|target| target.strip_suffix(']'))
            .and_then(|target| target.parse().ok())
            .expect("worker socket descriptor target is malformed");
        *socket_inodes.entry(inode).or_default() += 1;
    }
    let mut multiplicity = socket_inodes.values().copied().collect::<Vec<_>>();
    multiplicity.sort_unstable();
    assert_eq!(
        sockets.len(),
        4,
        "confined product worker descriptors: {descriptors:?}"
    );
    assert_eq!(multiplicity, [1, 1, 2]);

    drop(guest);
    let status = child.0.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(NetworkWorkerStartupFailure::FrameIo.exit_code())
    );
}

fn read_status_frame(stream: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    read_status_frame_result(stream).unwrap()
}

fn read_status_frame_result(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(WORKER_STATUS_MAX_BYTES);
    loop {
        assert!(frame.len() < WORKER_STATUS_MAX_BYTES);
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        frame.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(frame);
        }
    }
}

fn send_descriptor(bootstrap: RawFd, network: RawFd) {
    let mut marker = [NETWORK_DESCRIPTOR_MARKER];
    let mut vector = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let mut control = ControlBuffer {
        bytes: [0_u8; CONTROL_BYTES],
    };
    let control_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize };
    assert!(control_space <= CONTROL_BYTES);
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = unsafe { control.bytes.as_mut_ptr().cast() };
    message.msg_controllen = control_space;
    let header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    assert!(!header.is_null());
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), network);
    }
    assert_eq!(
        unsafe { libc::sendmsg(bootstrap, &raw const message, libc::MSG_NOSIGNAL) },
        marker.len() as isize
    );
}
