#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install-linux-containment-broker.sh must run as root" >&2
  exit 1
fi
if [ "$#" -ne 1 ]; then
  echo "usage: install-linux-containment-broker.sh DAEMON_USER" >&2
  exit 2
fi

daemon_user=$1
payload_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
payload_cli="$payload_root/cockpit"
payload_broker="$payload_root/cockpit-containment-broker"
status_cli=$payload_cli
if [ -x /usr/bin/cockpit ]; then status_cli=/usr/bin/cockpit; fi
daemon_uid=$(id -u "$daemon_user")
daemon_gid=$(id -g "$daemon_user")
case "$daemon_uid:$daemon_gid" in
  *[!0-9:]*|:*) echo "daemon account did not resolve to numeric uid/gid" >&2; exit 1 ;;
esac

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
if systemctl is-active --quiet "$broker_unit"; then broker_was_active=1; fi
if systemctl is-active --quiet "$daemon_unit"; then daemon_was_active=1; fi
if [ "$daemon_was_active" -eq 0 ] \
  && runuser -u "$daemon_user" -- "$status_cli" daemon status --json >/dev/null 2>&1
then
  detached_was_active=1
fi
transaction=$(mktemp -d /tmp/flycockpit-containment-install.XXXXXX)
committed=0

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
      if [ -f "$transaction/$name.previous" ]; then
        install -m "$(stat -c '%a' "$transaction/$name.previous")" "$transaction/$name.previous" "$destination"
      elif [ -f "$transaction/$name.created" ]; then
        rm -f "$destination"
      fi
    done
    systemctl daemon-reload 2>/dev/null || true
    restore_enablement "$broker_unit" "$broker_enablement"
    restore_enablement "$daemon_unit" "$daemon_enablement"
    if [ -f "$transaction/capability.created" ]; then
      rm -f "/etc/flycockpit/containment-capability-$daemon_uid"
    fi
    if [ "$broker_was_active" -eq 1 ]; then
      systemctl start "$broker_unit" 2>/dev/null || true
    fi
    if [ "$daemon_was_active" -eq 1 ]; then
      systemctl start "$daemon_unit" 2>/dev/null || true
    elif [ "$detached_was_active" -eq 1 ] && [ -x /usr/bin/cockpit ]; then
      runuser -u "$daemon_user" -- /usr/bin/cockpit daemon start 2>/dev/null || true
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
  # Address the daemon through its canonical runtime endpoint. This also finds
  # installs whose launching executable lived outside Cargo home or /usr/bin.
  runuser -u "$daemon_user" -- "$status_cli" daemon stop --grace 30
fi
if systemctl is-active --quiet "$daemon_unit" || systemctl is-active --quiet "$broker_unit"; then
  echo "refusing to install while an old managed service remains active" >&2
  exit 1
fi
if runuser -u "$daemon_user" -- "$status_cli" daemon status --json >/dev/null 2>&1; then
  echo "refusing to install while a detached daemon remains active" >&2
  exit 1
fi

install -d -m 0755 /etc/flycockpit /usr/libexec/flycockpit /usr/lib/systemd/system /usr/lib/tmpfiles.d

stage_install() {
  source=$1
  destination=$2
  mode=$3
  name=$(printf '%s' "$destination" | tr '/' '_')
  if [ -e "$destination" ]; then
    cp -a "$destination" "$transaction/$name.previous"
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

capability=/etc/flycockpit/containment-capability-$daemon_uid
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
