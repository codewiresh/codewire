#include "CCanarySupport.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCode.h>
#include <Security/SecRequirement.h>
#include <Security/SecStaticCode.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int copy_unix_address(const char *path, struct sockaddr_un *address) {
  size_t length;

  if (path == NULL || address == NULL) {
    errno = EINVAL;
    return -1;
  }
  length = strlen(path);
  if (length == 0 || length >= sizeof(address->sun_path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  memset(address, 0, sizeof(*address));
  address->sun_family = AF_UNIX;
  memcpy(address->sun_path, path, length + 1);
  return 0;
}

int cw_canary_listen(const char *path) {
  struct sockaddr_un address;
  int descriptor;

  if (copy_unix_address(path, &address) != 0) {
    return -1;
  }
  descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    return -1;
  }
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
      bind(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      chmod(path, S_IRUSR | S_IWUSR) != 0 || listen(descriptor, 1) != 0) {
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return -1;
  }
  return descriptor;
}

int cw_canary_connect(const char *path) {
  struct sockaddr_un address;
  int descriptor;

  if (copy_unix_address(path, &address) != 0) {
    return -1;
  }
  descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) {
    return -1;
  }
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
      connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return -1;
  }
  return descriptor;
}

int cw_canary_accept(int listener_fd, int timeout_milliseconds) {
  struct pollfd poll_descriptor = {
      .fd = listener_fd,
      .events = POLLIN,
  };
  int result;
  int descriptor;

  do {
    result = poll(&poll_descriptor, 1, timeout_milliseconds);
  } while (result < 0 && errno == EINTR);
  if (result <= 0) {
    if (result == 0) {
      errno = ETIMEDOUT;
    }
    return -1;
  }
  descriptor = accept(listener_fd, NULL, NULL);
  if (descriptor < 0) {
    return -1;
  }
  if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) {
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return -1;
  }
  return descriptor;
}

int cw_canary_spawn(const char *executable, int control_fd, pid_t *pid_out) {
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  sigset_t defaults;
  sigset_t mask;
  short flags = POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP |
                POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
  char *const arguments[] = {(char *)executable, NULL};
  char *const environment[] = {"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin",
                               NULL};
  int error;

  if (executable == NULL || control_fd < 0 || pid_out == NULL) {
    return EINVAL;
  }
  if ((error = posix_spawn_file_actions_init(&actions)) != 0) {
    return error;
  }
  if ((error = posix_spawnattr_init(&attributes)) != 0) {
    posix_spawn_file_actions_destroy(&actions);
    return error;
  }
  if ((error = posix_spawn_file_actions_adddup2(&actions, control_fd, 3)) !=
          0 ||
      (control_fd != 3 && (error = posix_spawn_file_actions_addclose(
                               &actions, control_fd)) != 0)) {
    goto done;
  }
  sigemptyset(&mask);
  sigemptyset(&defaults);
  sigaddset(&defaults, SIGALRM);
  sigaddset(&defaults, SIGHUP);
  sigaddset(&defaults, SIGINT);
  sigaddset(&defaults, SIGPIPE);
  sigaddset(&defaults, SIGTERM);
  if ((error = posix_spawnattr_setsigmask(&attributes, &mask)) != 0 ||
      (error = posix_spawnattr_setsigdefault(&attributes, &defaults)) != 0 ||
      (error = posix_spawnattr_setpgroup(&attributes, 0)) != 0 ||
      (error = posix_spawnattr_setflags(&attributes, flags)) != 0) {
    goto done;
  }
  error = posix_spawn(pid_out, executable, &actions, &attributes, arguments,
                      environment);

done:
  posix_spawnattr_destroy(&attributes);
  posix_spawn_file_actions_destroy(&actions);
  return error;
}

int cw_canary_normalize_sigchld(void) {
  struct sigaction action;
  sigset_t mask;

  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  sigemptyset(&action.sa_mask);
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigaction(SIGCHLD, &action, NULL) != 0 ||
      sigprocmask(SIG_UNBLOCK, &mask, NULL) != 0) {
    return -1;
  }
  return 0;
}

int cw_canary_child_live(pid_t pid) {
  siginfo_t information;
  int result;

  memset(&information, 0, sizeof(information));
  do {
    result =
        waitid(P_PID, (id_t)pid, &information, WEXITED | WNOHANG | WNOWAIT);
  } while (result != 0 && errno == EINTR);
  if (result != 0) {
    return -1;
  }
  return information.si_pid == 0 ? 1 : 0;
}

int cw_canary_wait(pid_t pid, int timeout_milliseconds, int *status_out) {
  int remaining = timeout_milliseconds;

  if (status_out == NULL || timeout_milliseconds < 0) {
    errno = EINVAL;
    return -1;
  }
  while (remaining >= 0) {
    pid_t result = waitpid(pid, status_out, WNOHANG);
    if (result == pid) {
      return 0;
    }
    if (result < 0 && errno != EINTR) {
      return -1;
    }
    if (remaining == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    int interval = remaining < 20 ? remaining : 20;
    usleep((useconds_t)interval * 1000);
    remaining -= interval;
  }
  errno = ETIMEDOUT;
  return -1;
}

static int signal_owned_group(pid_t pid, int signal_number) {
  if (pid <= 1) {
    errno = EINVAL;
    return -1;
  }
  return kill(-pid, signal_number);
}

int cw_canary_cleanup_child(pid_t pid) {
  int status = 0;
  int live;

  if (pid <= 1) {
    errno = EINVAL;
    return CW_CANARY_CLEANUP_UNKNOWN;
  }
  live = cw_canary_child_live(pid);
  if (live < 0) {
    return CW_CANARY_CLEANUP_UNKNOWN;
  }
  if (live == 0) {
    return cw_canary_wait(pid, 0, &status) == 0 ? CW_CANARY_CLEANUP_COMPLETE
                                                : CW_CANARY_CLEANUP_UNKNOWN;
  }
  if (signal_owned_group(pid, SIGTERM) != 0) {
    return CW_CANARY_CLEANUP_UNKNOWN;
  }
  if (cw_canary_wait(pid, 1000, &status) == 0) {
    return CW_CANARY_CLEANUP_COMPLETE;
  }
  if (errno != ETIMEDOUT) {
    return CW_CANARY_CLEANUP_UNKNOWN;
  }

  live = cw_canary_child_live(pid);
  if (live < 0) {
    return CW_CANARY_CLEANUP_UNKNOWN;
  }
  if (live == 0) {
    return cw_canary_wait(pid, 0, &status) == 0 ? CW_CANARY_CLEANUP_COMPLETE
                                                : CW_CANARY_CLEANUP_UNKNOWN;
  }
  if (signal_owned_group(pid, SIGKILL) != 0) {
    return CW_CANARY_CLEANUP_UNKNOWN;
  }
  return cw_canary_wait(pid, 1000, &status) == 0 ? CW_CANARY_CLEANUP_COMPLETE
                                                 : CW_CANARY_CLEANUP_UNKNOWN;
}

static int write_all(int descriptor, const uint8_t *bytes, size_t length) {
  size_t offset = 0;

  while (offset < length) {
    ssize_t amount = write(descriptor, bytes + offset, length - offset);
    if (amount < 0 && errno == EINTR) {
      continue;
    }
    if (amount <= 0) {
      return -1;
    }
    offset += (size_t)amount;
  }
  return 0;
}

int cw_canary_replace_checkpoint(const char *path, const uint8_t *bytes,
                                 size_t length) {
  char next_path[PATH_MAX];
  char parent_path[PATH_MAX];
  const char *slash;
  struct stat status;
  int descriptor = -1;
  int parent_descriptor = -1;
  int created = 0;
  int renamed = 0;
  int result = -1;

  if (path == NULL || bytes == NULL || length == 0 || length > 4096 ||
      path[0] != '/') {
    errno = EINVAL;
    return -1;
  }
  slash = strrchr(path, '/');
  if (slash == NULL || slash[1] == '\0' || strcmp(slash + 1, ".") == 0 ||
      strcmp(slash + 1, "..") == 0 ||
      strlen(path) + strlen(".next") >= PATH_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (slash == path) {
    memcpy(parent_path, "/", 2);
  } else {
    size_t parent_length = (size_t)(slash - path);
    if (parent_length >= sizeof(parent_path)) {
      errno = ENAMETOOLONG;
      return -1;
    }
    memcpy(parent_path, path, parent_length);
    parent_path[parent_length] = '\0';
  }
  if (snprintf(next_path, sizeof(next_path), "%s.next", path) < 0) {
    errno = EINVAL;
    return -1;
  }

  parent_descriptor =
      open(parent_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (parent_descriptor < 0) {
    return -1;
  }
  if (lstat(path, &status) == 0) {
    if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
        status.st_nlink != 1 || (status.st_mode & 0777) != 0600) {
      errno = EPERM;
      goto done;
    }
  } else if (errno != ENOENT) {
    goto done;
  }
  descriptor =
      open(next_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
           S_IRUSR | S_IWUSR);
  if (descriptor < 0) {
    goto done;
  }
  created = 1;
  if (fstat(descriptor, &status) != 0) {
    goto done;
  }
  if (!S_ISREG(status.st_mode) || status.st_uid != geteuid() ||
      status.st_nlink != 1 || (status.st_mode & 0777) != 0600) {
    errno = EPERM;
    goto done;
  }
  if (write_all(descriptor, bytes, length) != 0 || fsync(descriptor) != 0) {
    goto done;
  }
  if (close(descriptor) != 0) {
    int saved_errno = errno;
    descriptor = -1;
    errno = saved_errno;
    goto done;
  }
  descriptor = -1;
  if (rename(next_path, path) != 0) {
    goto done;
  }
  renamed = 1;
  if (fsync(parent_descriptor) != 0) {
    goto done;
  }
  result = 0;

done: {
  int saved_errno = errno;
  if (descriptor >= 0) {
    close(descriptor);
  }
  if (created && !renamed) {
    unlink(next_path);
  }
  close(parent_descriptor);
  errno = saved_errno;
}
  return result;
}

static int dictionary_is_empty(CFTypeRef value) {
  return value == NULL || (CFGetTypeID(value) == CFDictionaryGetTypeID() &&
                           CFDictionaryGetCount((CFDictionaryRef)value) == 0);
}

static int copy_signing_information(SecStaticCodeRef code,
                                    CFDictionaryRef *information) {
  OSStatus status = SecCodeCopySigningInformation(
      code, kSecCSSigningInformation, information);
  return status == errSecSuccess && *information != NULL;
}

static CFDataRef copy_cdhash(const char *hex) {
  size_t length;
  UInt8 bytes[64];

  if (hex == NULL) {
    return NULL;
  }
  length = strlen(hex);
  if (length < 40 || length > sizeof(bytes) * 2 || length % 2 != 0) {
    return NULL;
  }
  for (size_t index = 0; index < length / 2; index++) {
    unsigned int value;
    if (sscanf(hex + index * 2, "%2x", &value) != 1) {
      return NULL;
    }
    bytes[index] = (UInt8)value;
  }
  return CFDataCreate(NULL, bytes, (CFIndex)(length / 2));
}

static int entitlements_are_exact(CFTypeRef value, int expected_sandboxed) {
  CFDictionaryRef dictionary;
  CFTypeRef sandbox;

  if (!expected_sandboxed) {
    return dictionary_is_empty(value);
  }
  if (value == NULL || CFGetTypeID(value) != CFDictionaryGetTypeID()) {
    return 0;
  }
  dictionary = (CFDictionaryRef)value;
  if (CFDictionaryGetCount(dictionary) != 1) {
    return 0;
  }
  sandbox =
      CFDictionaryGetValue(dictionary, CFSTR("com.apple.security.app-sandbox"));
  return sandbox != NULL && CFGetTypeID(sandbox) == CFBooleanGetTypeID() &&
         CFBooleanGetValue((CFBooleanRef)sandbox);
}

int cw_canary_verify_direct_child(pid_t pid, const char *expected_bundle,
                                  const char *expected_executable,
                                  const char *expected_identifier,
                                  const char *expected_cdhash,
                                  int expected_sandboxed) {
  CFNumberRef pid_number = NULL;
  CFDictionaryRef attributes = NULL;
  SecCodeRef guest = NULL;
  SecStaticCodeRef dynamic_static = NULL;
  SecRequirementRef hash_requirement = NULL;
  CFURLRef expected_url = NULL;
  CFURLRef expected_executable_url = NULL;
  CFURLRef dynamic_url = NULL;
  CFStringRef dynamic_path = NULL;
  CFStringRef expected_path = NULL;
  CFDictionaryRef dynamic_info = NULL;
  CFDataRef pinned_cdhash = NULL;
  CFStringRef cdhash_string = NULL;
  CFStringRef requirement_string = NULL;
  CFStringRef required_identifier = NULL;
  int result = CW_CANARY_IDENTITY;

  if (pid <= 1 || expected_bundle == NULL || expected_executable == NULL ||
      expected_identifier == NULL || expected_cdhash == NULL ||
      (expected_sandboxed != 0 && expected_sandboxed != 1)) {
    return CW_CANARY_INVALID;
  }
  if (cw_canary_child_live(pid) != 1) {
    return CW_CANARY_IDENTITY;
  }
  pid_number = CFNumberCreate(NULL, kCFNumberIntType, &pid);
  pinned_cdhash = copy_cdhash(expected_cdhash);
  cdhash_string =
      CFStringCreateWithCString(NULL, expected_cdhash, kCFStringEncodingASCII);
  required_identifier = CFStringCreateWithCString(NULL, expected_identifier,
                                                  kCFStringEncodingUTF8);
  if (cdhash_string != NULL) {
    requirement_string = CFStringCreateWithFormat(
        NULL, NULL, CFSTR("cdhash H\"%@\""), cdhash_string);
  }
  if (pid_number == NULL || pinned_cdhash == NULL || cdhash_string == NULL ||
      required_identifier == NULL || requirement_string == NULL ||
      SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags,
                                     &hash_requirement) != errSecSuccess) {
    result = CW_CANARY_SYSTEM;
    goto done;
  }
  const void *attribute_keys[] = {kSecGuestAttributePid};
  const void *attribute_values[] = {pid_number};
  attributes = CFDictionaryCreate(NULL, attribute_keys, attribute_values, 1,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
  expected_url = CFURLCreateFromFileSystemRepresentation(
      NULL, (const UInt8 *)expected_bundle, strlen(expected_bundle), true);
  expected_executable_url = CFURLCreateFromFileSystemRepresentation(
      NULL, (const UInt8 *)expected_executable, strlen(expected_executable),
      false);
  if (attributes == NULL || expected_url == NULL ||
      expected_executable_url == NULL) {
    result = CW_CANARY_SYSTEM;
    goto done;
  }
  if (SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags,
                                     &guest) != errSecSuccess ||
      SecCodeCheckValidity(guest, kSecCSStrictValidate, hash_requirement) !=
          errSecSuccess ||
      SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &dynamic_static) !=
          errSecSuccess ||
      SecStaticCodeCheckValidity(
          dynamic_static, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
          hash_requirement) != errSecSuccess ||
      SecCodeCopyPath(dynamic_static, kSecCSDefaultFlags, &dynamic_url) !=
          errSecSuccess ||
      !copy_signing_information(dynamic_static, &dynamic_info)) {
    goto done;
  }
  dynamic_path = CFURLCopyFileSystemPath(dynamic_url, kCFURLPOSIXPathStyle);
  expected_path = CFURLCopyFileSystemPath(expected_url, kCFURLPOSIXPathStyle);
  CFTypeRef dynamic_identifier =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoIdentifier);
  CFTypeRef dynamic_unique =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoUnique);
  CFTypeRef dynamic_executable =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoMainExecutable);
  CFTypeRef dynamic_entitlements =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoEntitlementsDict);

  if (dynamic_path != NULL && expected_path != NULL &&
      CFEqual(dynamic_path, expected_path) && dynamic_identifier != NULL &&
      CFEqual(dynamic_identifier, required_identifier) &&
      dynamic_unique != NULL &&
      CFGetTypeID(dynamic_unique) == CFDataGetTypeID() &&
      CFEqual(dynamic_unique, pinned_cdhash) && dynamic_executable != NULL &&
      CFEqual(dynamic_executable, expected_executable_url) &&
      entitlements_are_exact(dynamic_entitlements, expected_sandboxed) &&
      cw_canary_child_live(pid) == 1) {
    result = CW_CANARY_OK;
  }

done:
  if (dynamic_info != NULL)
    CFRelease(dynamic_info);
  if (expected_path != NULL)
    CFRelease(expected_path);
  if (dynamic_path != NULL)
    CFRelease(dynamic_path);
  if (dynamic_url != NULL)
    CFRelease(dynamic_url);
  if (expected_executable_url != NULL)
    CFRelease(expected_executable_url);
  if (expected_url != NULL)
    CFRelease(expected_url);
  if (hash_requirement != NULL)
    CFRelease(hash_requirement);
  if (dynamic_static != NULL)
    CFRelease(dynamic_static);
  if (guest != NULL)
    CFRelease(guest);
  if (attributes != NULL)
    CFRelease(attributes);
  if (pid_number != NULL)
    CFRelease(pid_number);
  if (pinned_cdhash != NULL)
    CFRelease(pinned_cdhash);
  if (cdhash_string != NULL)
    CFRelease(cdhash_string);
  if (requirement_string != NULL)
    CFRelease(requirement_string);
  if (required_identifier != NULL)
    CFRelease(required_identifier);
  return result;
}

int cw_canary_verify_connected_peer(int connected_fd, pid_t expected_pid,
                                    const char *expected_bundle,
                                    const char *expected_executable,
                                    const char *expected_identifier,
                                    const char *expected_cdhash) {
  audit_token_t token;
  socklen_t token_length = sizeof(token);
  pid_t peer_pid = 0;
  socklen_t pid_length = sizeof(peer_pid);
  CFDataRef token_data = NULL;
  CFDictionaryRef attributes = NULL;
  SecCodeRef guest = NULL;
  SecStaticCodeRef dynamic_static = NULL;
  SecStaticCodeRef expected_static = NULL;
  SecRequirementRef expected_requirement = NULL;
  SecRequirementRef hash_requirement = NULL;
  CFURLRef expected_url = NULL;
  CFURLRef expected_executable_url = NULL;
  CFURLRef dynamic_url = NULL;
  CFStringRef dynamic_path = NULL;
  CFStringRef expected_path = NULL;
  CFDictionaryRef dynamic_info = NULL;
  CFDictionaryRef expected_info = NULL;
  CFDataRef pinned_cdhash = NULL;
  CFStringRef cdhash_string = NULL;
  CFStringRef requirement_string = NULL;
  int result = CW_CANARY_IDENTITY;

  if (connected_fd < 0 || expected_pid <= 1 || expected_bundle == NULL ||
      expected_executable == NULL || expected_identifier == NULL ||
      expected_cdhash == NULL) {
    return CW_CANARY_INVALID;
  }
  if (getsockopt(connected_fd, SOL_LOCAL, LOCAL_PEERPID, &peer_pid,
                 &pid_length) != 0 ||
      getsockopt(connected_fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token,
                 &token_length) != 0) {
    return CW_CANARY_SYSTEM;
  }
  if (pid_length != sizeof(peer_pid) || token_length != sizeof(token) ||
      peer_pid != expected_pid || audit_token_to_pid(token) != expected_pid) {
    return CW_CANARY_IDENTITY;
  }

  token_data = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
  pinned_cdhash = copy_cdhash(expected_cdhash);
  cdhash_string =
      CFStringCreateWithCString(NULL, expected_cdhash, kCFStringEncodingASCII);
  if (cdhash_string != NULL) {
    requirement_string = CFStringCreateWithFormat(
        NULL, NULL, CFSTR("cdhash H\"%@\""), cdhash_string);
  }
  if (token_data == NULL || pinned_cdhash == NULL ||
      requirement_string == NULL ||
      SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags,
                                     &hash_requirement) != errSecSuccess) {
    result = CW_CANARY_SYSTEM;
    goto done;
  }
  const void *attribute_keys[] = {kSecGuestAttributeAudit};
  const void *attribute_values[] = {token_data};
  attributes = CFDictionaryCreate(NULL, attribute_keys, attribute_values, 1,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
  expected_url = CFURLCreateFromFileSystemRepresentation(
      NULL, (const UInt8 *)expected_bundle, strlen(expected_bundle), true);
  expected_executable_url = CFURLCreateFromFileSystemRepresentation(
      NULL, (const UInt8 *)expected_executable, strlen(expected_executable),
      false);
  if (attributes == NULL || expected_url == NULL ||
      expected_executable_url == NULL) {
    result = CW_CANARY_SYSTEM;
    goto done;
  }
  if (SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags,
                                     &guest) != errSecSuccess ||
      SecCodeCopyStaticCode(guest, kSecCSDefaultFlags, &dynamic_static) !=
          errSecSuccess ||
      SecStaticCodeCreateWithPath(expected_url, kSecCSDefaultFlags,
                                  &expected_static) != errSecSuccess ||
      SecStaticCodeCheckValidity(
          expected_static, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
          NULL) != errSecSuccess ||
      SecCodeCopyDesignatedRequirement(expected_static, kSecCSDefaultFlags,
                                       &expected_requirement) !=
          errSecSuccess ||
      SecCodeCheckValidity(guest, kSecCSStrictValidate, expected_requirement) !=
          errSecSuccess ||
      SecCodeCheckValidity(guest, kSecCSStrictValidate, hash_requirement) !=
          errSecSuccess ||
      SecCodeCopyPath(dynamic_static, kSecCSDefaultFlags, &dynamic_url) !=
          errSecSuccess ||
      !copy_signing_information(dynamic_static, &dynamic_info) ||
      !copy_signing_information(expected_static, &expected_info)) {
    goto done;
  }

  dynamic_path = CFURLCopyFileSystemPath(dynamic_url, kCFURLPOSIXPathStyle);
  expected_path = CFURLCopyFileSystemPath(expected_url, kCFURLPOSIXPathStyle);
  CFTypeRef dynamic_identifier =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoIdentifier);
  CFTypeRef expected_identifier_value =
      CFDictionaryGetValue(expected_info, kSecCodeInfoIdentifier);
  CFTypeRef dynamic_unique =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoUnique);
  CFTypeRef expected_unique =
      CFDictionaryGetValue(expected_info, kSecCodeInfoUnique);
  CFTypeRef dynamic_executable =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoMainExecutable);
  CFTypeRef expected_executable_value =
      CFDictionaryGetValue(expected_info, kSecCodeInfoMainExecutable);
  CFTypeRef dynamic_entitlements =
      CFDictionaryGetValue(dynamic_info, kSecCodeInfoEntitlementsDict);
  CFTypeRef expected_entitlements =
      CFDictionaryGetValue(expected_info, kSecCodeInfoEntitlementsDict);
  CFStringRef required_identifier = CFStringCreateWithCString(
      NULL, expected_identifier, kCFStringEncodingUTF8);

  if (dynamic_path != NULL && expected_path != NULL &&
      required_identifier != NULL && CFEqual(dynamic_path, expected_path) &&
      dynamic_identifier != NULL && expected_identifier_value != NULL &&
      CFEqual(dynamic_identifier, required_identifier) &&
      CFEqual(expected_identifier_value, required_identifier) &&
      dynamic_unique != NULL && expected_unique != NULL &&
      CFGetTypeID(dynamic_unique) == CFDataGetTypeID() &&
      CFGetTypeID(expected_unique) == CFDataGetTypeID() &&
      CFEqual(dynamic_unique, expected_unique) &&
      CFEqual(dynamic_unique, pinned_cdhash) && dynamic_executable != NULL &&
      expected_executable_value != NULL &&
      CFEqual(dynamic_executable, expected_executable_url) &&
      CFEqual(expected_executable_value, expected_executable_url) &&
      dictionary_is_empty(dynamic_entitlements) &&
      dictionary_is_empty(expected_entitlements)) {
    result = CW_CANARY_OK;
  }
  if (required_identifier != NULL) {
    CFRelease(required_identifier);
  }

done:
  if (expected_info != NULL)
    CFRelease(expected_info);
  if (dynamic_info != NULL)
    CFRelease(dynamic_info);
  if (expected_path != NULL)
    CFRelease(expected_path);
  if (dynamic_path != NULL)
    CFRelease(dynamic_path);
  if (dynamic_url != NULL)
    CFRelease(dynamic_url);
  if (expected_url != NULL)
    CFRelease(expected_url);
  if (expected_executable_url != NULL)
    CFRelease(expected_executable_url);
  if (expected_static != NULL)
    CFRelease(expected_static);
  if (expected_requirement != NULL)
    CFRelease(expected_requirement);
  if (hash_requirement != NULL)
    CFRelease(hash_requirement);
  if (dynamic_static != NULL)
    CFRelease(dynamic_static);
  if (guest != NULL)
    CFRelease(guest);
  if (attributes != NULL)
    CFRelease(attributes);
  if (token_data != NULL)
    CFRelease(token_data);
  if (pinned_cdhash != NULL)
    CFRelease(pinned_cdhash);
  if (cdhash_string != NULL)
    CFRelease(cdhash_string);
  if (requirement_string != NULL)
    CFRelease(requirement_string);
  return result;
}
