#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: install-linux-containment-broker.sh DAEMON_USER" >&2
  exit 2
fi
# Resolve every external prerequisite before its first use. In particular,
# `id`, systemd tooling, and bundle-verification tooling cannot be deferred
# until after they have already influenced privileged control flow.
for tool in id getent awk sed stat readlink tr cut grep sha256sum readelf uname \
  systemctl systemd-analyze systemd-run systemd-tmpfiles dirname sort mktemp cp \
  find basename mkdir ln rm sleep rmdir runuser env install chown mv dd chmod; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required containment installer tool is unavailable: $tool" >&2
    exit 1
  fi
done
if [ "$(id -u)" -ne 0 ]; then
  echo "install-linux-containment-broker.sh must run as root" >&2
  exit 1
fi

daemon_user=$1
payload_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
payload_cli="$payload_root/cockpit"
payload_broker="$payload_root/cockpit-containment-broker"
daemon_uid=$(id -u "$daemon_user")
daemon_gid=$(id -g "$daemon_user")
daemon_home=$(getent passwd "$daemon_user" | awk -F: 'NR == 1 { print $6 }')
if [ -z "$daemon_home" ] || [ ! -d "$daemon_home" ]; then
  echo "daemon account home directory is unavailable" >&2
  exit 1
fi
capability=/etc/flycockpit/containment-capability-$daemon_uid
case "$daemon_uid:$daemon_gid" in
  *[!0-9:]*|:*) echo "daemon account did not resolve to numeric uid/gid" >&2; exit 1 ;;
esac
if [ "$daemon_uid" -eq 0 ]; then
  echo "the managed FlyCockpit daemon must use a dedicated non-root account" >&2
  exit 1
fi

for source in "$payload_cli" "$payload_broker" \
  "$payload_root/infra/systemd/cockpit-containment-broker@.service" \
  "$payload_root/infra/systemd/cockpit-daemon@.service" \
  "$payload_root/infra/tmpfiles.d/flycockpit-containment.conf"
do
  if [ ! -f "$source" ]; then
    echo "missing release artifact: $source" >&2
    exit 1
  fi
done

# Authenticate and identify the complete extracted bundle before stopping a
# daemon or writing any privileged path. This installer is Linux-only, so its
# verification tools are explicit prerequisites, never weaker fallbacks.
bundle_target=$(sed -n '1p' "$payload_root/TARGET" 2>/dev/null || true)
case "$(uname -m):$bundle_target" in
  x86_64:x86_64-unknown-linux-gnu|aarch64:aarch64-unknown-linux-gnu) ;;
  *) echo "containment bundle target '$bundle_target' does not match host architecture '$(uname -m)'" >&2; exit 1 ;;
esac
if [ ! -s "$payload_root/RELEASE" ] || [ ! -f "$payload_root/MANIFEST.sha256" ]; then
  echo "containment bundle release metadata is missing" >&2
  exit 1
fi
if ! (cd "$payload_root" && sha256sum --strict --check MANIFEST.sha256 >/dev/null); then
  echo "containment bundle member verification failed" >&2
  exit 1
fi
manifest_members=$(sed -n 's/^[0-9a-fA-F]\{64\}[[:space:]][ *]\{0,1\}//p' "$payload_root/MANIFEST.sha256" | LC_ALL=C sort)
expected_members=$(printf '%s\n' \
  RELEASE TARGET cockpit cockpit-containment-broker \
  infra/systemd/cockpit-containment-broker@.service \
  infra/systemd/cockpit-daemon@.service \
  infra/tmpfiles.d/flycockpit-containment.conf \
  install-linux-containment-broker.sh | LC_ALL=C sort)
if [ "$manifest_members" != "$expected_members" ]; then
  echo "containment bundle manifest does not cover the exact release payload" >&2
  exit 1
fi
expected_machine=$(case "$bundle_target" in x86_64-*) echo Advanced Micro Devices X86-64;; aarch64-*) echo AArch64;; esac)
for binary in "$payload_cli" "$payload_broker"; do
  if [ ! -f "$binary" ] || [ -L "$binary" ] || [ ! -x "$binary" ] \
    || ! readelf -h "$binary" 2>/dev/null | grep -F "Machine:" | grep -F "$expected_machine" >/dev/null
  then
    echo "bundle executable is invalid for $bundle_target: $binary" >&2
    exit 1
  fi
done
if [ -L "$capability" ]; then
  echo "existing containment capability must not be a symlink" >&2
  exit 1
fi
if [ -e "$capability" ] && [ "$(stat -c '%u:%g:%a:%s' "$capability")" != "0:0:400:32" ]; then
  echo "existing containment capability has unsafe ownership, mode, or size" >&2
  exit 1
fi

systemd_version=$(systemd-analyze --version | sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
if [ -z "$systemd_version" ] || [ "$systemd_version" -lt 253 ]; then
  echo "FlyCockpit containment requires systemd 253 or newer (OpenFile=)" >&2
  exit 1
fi
broker_unit="cockpit-containment-broker@$daemon_uid.service"
daemon_unit="cockpit-daemon@$daemon_uid.service"
broker_was_active=0
daemon_was_active=0
broker_enablement=$(systemctl is-enabled "$broker_unit" 2>/dev/null || true)
daemon_enablement=$(systemctl is-enabled "$daemon_unit" 2>/dev/null || true)
detached_was_active=0
detached_control_executable=
detached_executable_source=
detached_control_socket=
detached_pid=
detached_starttime=
detached_runtime_dir=
if systemctl is-active --quiet "$broker_unit"; then broker_was_active=1; fi
if systemctl is-active --quiet "$daemon_unit"; then daemon_was_active=1; fi
if [ "$daemon_was_active" -eq 0 ]; then
  # Discover the old authority from its stable endpoint record and kernel
  # identity. Never ask the new payload (or an arbitrary PATH binary) to speak
  # an old daemon protocol: upgrades must remain possible across incompatible
  # prerelease wire versions.
  daemon_state="$daemon_home/.local/state/cockpit"
  endpoint_record="$daemon_state/daemon-endpoint.json"
  pid_record="$daemon_state/daemon.pid"
  endpoint_pid=
  endpoint_socket=
  file_pid=
  if [ -f "$endpoint_record" ]; then
    endpoint_pid=$(sed -n 's/.*"pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$endpoint_record")
    endpoint_socket=$(sed -n 's/.*"socket"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$endpoint_record")
  fi
  if [ -f "$pid_record" ]; then file_pid=$(sed -n '1s/^\([0-9][0-9]*\)$/\1/p' "$pid_record"); fi
  if [ -n "$endpoint_pid" ] && [ -n "$file_pid" ] && [ "$endpoint_pid" != "$file_pid" ]; then
    echo "ambiguous detached daemon authority: endpoint and pid records disagree" >&2
    exit 1
  fi
  if [ -z "$endpoint_socket" ]; then
    runtime_socket="/run/user/$daemon_uid/cockpit/cockpit.sock"
    state_socket="$daemon_state/daemon.sock"
    socket_candidates=0
    if [ -S "$runtime_socket" ]; then endpoint_socket=$runtime_socket; socket_candidates=$((socket_candidates + 1)); fi
    if [ -S "$state_socket" ]; then endpoint_socket=$state_socket; socket_candidates=$((socket_candidates + 1)); fi
    if [ "$socket_candidates" -gt 1 ]; then
      echo "ambiguous detached daemon authority: multiple canonical sockets exist" >&2
      exit 1
    fi
  fi
  detached_pid=${endpoint_pid:-$file_pid}
  daemon_process_candidates=0
  for process_status in /proc/[0-9]*/status; do
    candidate_uid=$(sed -n 's/^Uid:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$process_status" 2>/dev/null || true)
    [ "$candidate_uid" = "$daemon_uid" ] || continue
    candidate_pid=${process_status#/proc/}; candidate_pid=${candidate_pid%/status}
    candidate_argv=$(tr '\000' ' ' <"/proc/$candidate_pid/cmdline" 2>/dev/null || true)
    case " $candidate_argv " in *" daemon start --foreground "*) daemon_process_candidates=$((daemon_process_candidates + 1)) ;; esac
  done
  if [ "$daemon_process_candidates" -gt 0 ] && [ -z "$detached_pid" ]; then
    echo "active daemon-like process has no unambiguous recorded authority" >&2
    exit 1
  fi
  if [ -n "$detached_pid" ] && kill -0 "$detached_pid" 2>/dev/null; then
    if [ -z "$endpoint_socket" ] || [ ! -S "$endpoint_socket" ]; then
      echo "active detached daemon has no unambiguous recorded control endpoint" >&2
      exit 1
    fi
    process_uid=$(sed -n 's/^Uid:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "/proc/$detached_pid/status" 2>/dev/null || true)
    process_argv=$(tr '\000' ' ' <"/proc/$detached_pid/cmdline" 2>/dev/null || true)
    socket_uid=$(stat -c '%u' "$endpoint_socket" 2>/dev/null || true)
    if [ "$process_uid" != "$daemon_uid" ] || [ "$socket_uid" != "$daemon_uid" ] \
      || ! printf '%s' " $process_argv " | grep -F " daemon start --foreground " >/dev/null; then
      echo "detached daemon process or endpoint is not owned by the daemon account" >&2
      exit 1
    fi
    detached_starttime=$(sed -n 's/^[^)]*) //' "/proc/$detached_pid/stat" | cut -d' ' -f20)
    if [ -z "$detached_starttime" ]; then
      echo "could not attest detached daemon process generation" >&2
      exit 1
    fi
    detached_control_socket=$endpoint_socket
    detached_executable_source="/proc/$detached_pid/exe"
    detached_control_executable=$(readlink "$detached_executable_source" 2>/dev/null || true)
    if [ -z "$detached_control_executable" ] || [ ! -x "$detached_executable_source" ]; then
      echo "could not snapshot the detached daemon control executable" >&2
      exit 1
    fi
    detached_was_active=1
    case "$detached_control_socket" in
      "$daemon_state/daemon.sock") detached_runtime_dir= ;;
      */cockpit/cockpit.sock) detached_runtime_dir=$(dirname "$(dirname "$detached_control_socket")") ;;
      *) echo "recorded detached daemon endpoint is not a canonical route" >&2; exit 1 ;;
    esac
  elif [ -n "$endpoint_socket" ] && [ -S "$endpoint_socket" ]; then
    echo "recorded detached daemon endpoint exists without its recorded process" >&2
    exit 1
  fi
fi
transaction=$(mktemp -d /tmp/flycockpit-containment-install.XXXXXX)
committed=0
if [ "$detached_was_active" -eq 1 ]; then
  cp --preserve=all "$detached_executable_source" "$transaction/detached-control-executable"
  printf '%s\n' "$detached_control_socket" >"$transaction/detached-control-socket"
  printf '%s\n' "$detached_runtime_dir" >"$transaction/detached-runtime-dir"
fi

# Record directory ownership before any service or tmpfiles action. Rollback
# removes only paths proven absent at transaction start; pre-existing shared
# directories and their contents are never claimed by this installer.
remember_missing_directory() {
  path=$1
  marker=$(printf '%s' "$path" | tr '/' '_')
  if [ ! -e "$path" ]; then : >"$transaction/dir$marker.created"; fi
}
for path in \
  /etc/flycockpit \
  /usr/libexec/flycockpit \
  /usr/lib/systemd/system \
  /usr/lib/tmpfiles.d \
  /run/flycockpit \
  /var/lib/flycockpit \
  "/var/lib/flycockpit/containment-broker-$daemon_uid" \
  /sys/fs/cgroup/flycockpit \
  "/sys/fs/cgroup/flycockpit/u$daemon_uid"
do
  remember_missing_directory "$path"
done

# Preserve actual enablement topology; `is-enabled` alone loses custom wants,
# aliases, runtime links, and masks.
snapshot_unit_links() {
  unit=$1
  output=$2
  : >"$output"
  for root in /etc/systemd/system /run/systemd/system; do
    [ -d "$root" ] || continue
    find "$root" -type l -print | while IFS= read -r link; do
      target=$(readlink "$link")
      case "$(basename "$link"):$(basename "$target")" in
        "$unit":*|*:"$unit") printf '%s\t%s\n' "$link" "$target" >>"$output" ;;
      esac
    done
  done
}

restore_unit_links() {
  unit=$1
  snapshot=$2
  for root in /etc/systemd/system /run/systemd/system; do
    [ -d "$root" ] || continue
    find "$root" -type l -print | while IFS= read -r link; do
      target=$(readlink "$link")
      case "$(basename "$link"):$(basename "$target")" in
        "$unit":*|*:"$unit") rm -f -- "$link" ;;
      esac
    done
  done
  while IFS="$(printf '\t')" read -r link target; do
    [ -n "$link" ] || continue
    mkdir -p "$(dirname "$link")"
    ln -s "$target" "$link"
  done <"$snapshot"
}

snapshot_unit_links "$broker_unit" "$transaction/broker.links"
snapshot_unit_links "$daemon_unit" "$transaction/daemon.links"

restore_enablement() {
  unit=$1
  state=$2
  case "$state" in
    enabled|linked) systemctl enable "$unit" 2>/dev/null || true ;;
    enabled-runtime|linked-runtime) systemctl enable --runtime "$unit" 2>/dev/null || true ;;
    alias|static|indirect|generated|transient) : ;;
    masked) systemctl mask "$unit" 2>/dev/null || true ;;
    masked-runtime) systemctl mask --runtime "$unit" 2>/dev/null || true ;;
    disabled|not-found|bad|'') systemctl disable "$unit" 2>/dev/null || true ;;
  esac
}

retry() {
  attempts=$1
  shift
  while ! "$@"; do
    attempts=$((attempts - 1))
    if [ "$attempts" -le 0 ]; then return 1; fi
    sleep 1
  done
}

socket_contract_ready() {
  [ -S "$socket" ] \
    && [ "$(stat -c '%F:%u:%g:%a' "$socket")" = "socket:0:$daemon_gid:660" ]
}

broker_protocol_ready() {
  systemd-run --quiet --wait --collect --pipe --service-type=exec \
    --unit="flycockpit-containment-doctor-$daemon_uid-$$" \
    --property="User=$daemon_uid" --property="Group=$daemon_gid" \
    --property="OpenFile=$capability:flycockpit-containment-capability:read-only" \
    /usr/libexec/flycockpit/cockpit-containment-broker \
      --doctor --allowed-uid "$daemon_uid" --socket "$socket" --capability-fd 3
}

rollback() {
  status=$?
  if [ "$committed" -eq 0 ]; then
    systemctl stop "$daemon_unit" "$broker_unit" 2>/dev/null || true
    for destination in /usr/bin/cockpit \
      /usr/libexec/flycockpit/cockpit-containment-broker \
      /usr/lib/systemd/system/cockpit-containment-broker@.service \
      /usr/lib/systemd/system/cockpit-daemon@.service \
      /usr/lib/tmpfiles.d/flycockpit-containment.conf
    do
      name=$(printf '%s' "$destination" | tr '/' '_')
      if [ -e "$transaction/$name.previous" ] || [ -L "$transaction/$name.previous" ]; then
        restored="$destination.flycockpit-restore-$$"
        rm -f -- "$restored"
        cp -a --preserve=all "$transaction/$name.previous" "$restored"
        mv -Tf "$restored" "$destination"
      elif [ -f "$transaction/$name.created" ]; then
        rm -f "$destination"
      fi
    done
    systemctl daemon-reload 2>/dev/null || true
    restore_enablement "$broker_unit" "$broker_enablement"
    restore_enablement "$daemon_unit" "$daemon_enablement"
    restore_unit_links "$broker_unit" "$transaction/broker.links"
    restore_unit_links "$daemon_unit" "$transaction/daemon.links"
    if [ -f "$transaction/capability.created" ]; then
      rm -f "/etc/flycockpit/containment-capability-$daemon_uid"
    fi
    # StateDirectory and tmpfiles may have materialized these after the file
    # transaction began. Remove only transaction-created, instance-exact
    # state; shared parents are removed only when empty.
    if [ -f "$transaction/dir_var_lib_flycockpit_containment-broker-$daemon_uid.created" ]; then
      rm -rf -- "/var/lib/flycockpit/containment-broker-$daemon_uid"
    fi
    for path in \
      "/sys/fs/cgroup/flycockpit/u$daemon_uid" \
      /sys/fs/cgroup/flycockpit \
      /run/flycockpit \
      /var/lib/flycockpit \
      /etc/flycockpit \
      /usr/libexec/flycockpit \
      /usr/lib/systemd/system \
      /usr/lib/tmpfiles.d
    do
      marker=$(printf '%s' "$path" | tr '/' '_')
      if [ -f "$transaction/dir$marker.created" ]; then rmdir -- "$path" 2>/dev/null || true; fi
    done
    if [ "$broker_was_active" -eq 1 ]; then
      systemctl start "$broker_unit" 2>/dev/null || true
    fi
    if [ "$daemon_was_active" -eq 1 ]; then
      systemctl start "$daemon_unit" 2>/dev/null || true
    elif [ "$detached_was_active" -eq 1 ] && [ -x "$transaction/detached-control-executable" ]; then
      restored_runtime=$(sed -n '1p' "$transaction/detached-runtime-dir")
      if [ -n "$restored_runtime" ]; then
        runuser -u "$daemon_user" -- env XDG_RUNTIME_DIR="$restored_runtime" \
          "$transaction/detached-control-executable" daemon start --detach 2>/dev/null || true
      else
        runuser -u "$daemon_user" -- env -u XDG_RUNTIME_DIR \
          "$transaction/detached-control-executable" daemon start --detach 2>/dev/null || true
      fi
      restored_socket=$(sed -n 's/.*"socket"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "$daemon_home/.local/state/cockpit/daemon-endpoint.json" 2>/dev/null || true)
      if [ "$restored_socket" != "$(sed -n '1p' "$transaction/detached-control-socket")" ] \
        || [ ! -S "$restored_socket" ]; then
        echo "error: detached daemon control route was not restored exactly" >&2
      fi
    fi
  fi
  rm -rf "$transaction"
  exit "$status"
}
trap rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$daemon_was_active" -eq 1 ]; then systemctl stop "$daemon_unit"; fi
if [ "$broker_was_active" -eq 1 ]; then systemctl stop "$broker_unit"; fi
if [ "$detached_was_active" -eq 1 ]; then
  # Signal the kernel-attested old process directly. This takeover path does
  # not depend on either the old or new CLI protocol.
  kill -TERM "$detached_pid"
  attempts=30
  while kill -0 "$detached_pid" 2>/dev/null \
    && [ "$(sed -n 's/^[^)]*) //' "/proc/$detached_pid/stat" 2>/dev/null | cut -d' ' -f20)" = "$detached_starttime" ]; do
    attempts=$((attempts - 1))
    if [ "$attempts" -le 0 ]; then
      echo "detached daemon did not stop within the takeover deadline" >&2
      exit 1
    fi
    sleep 1
  done
fi
if systemctl is-active --quiet "$daemon_unit" || systemctl is-active --quiet "$broker_unit"; then
  echo "refusing to install while an old managed service remains active" >&2
  exit 1
fi
if [ -n "$detached_pid" ] && kill -0 "$detached_pid" 2>/dev/null \
  && [ "$(sed -n 's/^[^)]*) //' "/proc/$detached_pid/stat" 2>/dev/null | cut -d' ' -f20)" = "$detached_starttime" ]; then
  echo "refusing to install while a detached daemon remains active" >&2
  exit 1
fi

install -d -m 0755 /etc/flycockpit /usr/libexec/flycockpit /usr/lib/systemd/system /usr/lib/tmpfiles.d

stage_install() {
  source=$1
  destination=$2
  mode=$3
  name=$(printf '%s' "$destination" | tr '/' '_')
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    cp -a --preserve=all "$destination" "$transaction/$name.previous"
  else
    : >"$transaction/$name.created"
  fi
  staged="$destination.flycockpit-new-$$"
  install -m "$mode" "$source" "$staged"
  chown root:root "$staged"
  mv -f "$staged" "$destination"
}

stage_install "$payload_cli" /usr/bin/cockpit 0755
stage_install "$payload_broker" /usr/libexec/flycockpit/cockpit-containment-broker 0755
stage_install "$payload_root/infra/systemd/cockpit-containment-broker@.service" /usr/lib/systemd/system/cockpit-containment-broker@.service 0644
stage_install "$payload_root/infra/systemd/cockpit-daemon@.service" /usr/lib/systemd/system/cockpit-daemon@.service 0644
stage_install "$payload_root/infra/tmpfiles.d/flycockpit-containment.conf" /usr/lib/tmpfiles.d/flycockpit-containment.conf 0644

# Verify the exact installed transaction, after both referenced executables
# exist. A clean host must not fail validation merely because /usr paths were
# absent before the transaction began.
systemd-analyze verify /usr/lib/systemd/system/cockpit-containment-broker@.service /usr/lib/systemd/system/cockpit-daemon@.service

if [ ! -e "$capability" ]; then
  umask 077
  capability_staged="$capability.flycockpit-new-$$"
  dd if=/dev/urandom of="$capability_staged" bs=32 count=1 status=none
  chown root:root "$capability_staged"
  chmod 0400 "$capability_staged"
  mv "$capability_staged" "$capability"
  : >"$transaction/capability.created"
fi
if [ "$(stat -c '%u:%g:%a:%s' "$capability")" != "0:0:400:32" ]; then
  echo "existing containment capability has unsafe ownership, mode, or size" >&2
  exit 1
fi

systemd-tmpfiles --create flycockpit-containment.conf
systemctl daemon-reload
systemctl enable "$broker_unit" "$daemon_unit"
systemctl start "$broker_unit"
socket="/run/flycockpit/containment-broker-$daemon_uid.sock"
if ! retry 30 socket_contract_ready; then
  echo "containment broker did not publish the authenticated socket contract" >&2
  exit 1
fi
# Run the protocol doctor under the exact daemon UID/GID and descriptor setup.
# The transient unit receives the root-only capability as the same named FD as
# the managed daemon; success therefore proves socket access, authentication,
# and the broker's Proven readiness from the daemon's security context.
if ! retry 30 broker_protocol_ready; then
  echo "containment broker did not become authenticated and Proven ready" >&2
  exit 1
fi
systemctl start "$daemon_unit"
retry 30 systemctl is-active --quiet "$daemon_unit"
retry 30 runuser -u "$daemon_user" -- /usr/bin/cockpit daemon status --json >/dev/null

committed=1
trap - EXIT HUP INT TERM
rm -rf "$transaction"
echo "Installed the FlyCockpit managed daemon and containment broker for $daemon_user (UID $daemon_uid)."
