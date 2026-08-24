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
daemon_uid=$(id -u "$daemon_user")
daemon_gid=$(id -g "$daemon_user")
case "$daemon_uid:$daemon_gid" in
  *[!0-9:]*|:*) echo "daemon account did not resolve to numeric uid/gid" >&2; exit 1 ;;
esac

for source in cockpit cockpit-containment-broker \
  infra/systemd/cockpit-containment-broker@.service \
  infra/systemd/cockpit-daemon@.service \
  infra/tmpfiles.d/flycockpit-containment.conf
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
systemd-analyze verify infra/systemd/cockpit-containment-broker@.service infra/systemd/cockpit-daemon@.service

broker_unit="cockpit-containment-broker@$daemon_uid.service"
daemon_unit="cockpit-daemon@$daemon_uid.service"
broker_was_active=0
daemon_was_active=0
broker_was_enabled=0
daemon_was_enabled=0
detached_was_active=0
if systemctl is-active --quiet "$broker_unit"; then broker_was_active=1; fi
if systemctl is-active --quiet "$daemon_unit"; then daemon_was_active=1; fi
if systemctl is-enabled --quiet "$broker_unit"; then broker_was_enabled=1; fi
if systemctl is-enabled --quiet "$daemon_unit"; then daemon_was_enabled=1; fi
if [ "$daemon_was_active" -eq 0 ] && [ -x /usr/bin/cockpit ] \
  && runuser -u "$daemon_user" -- /usr/bin/cockpit daemon status --json >/dev/null 2>&1
then
  detached_was_active=1
fi
transaction=$(mktemp -d /tmp/flycockpit-containment-install.XXXXXX)
committed=0

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
    if [ "$broker_was_enabled" -eq 1 ]; then
      systemctl enable "$broker_unit" 2>/dev/null || true
    else
      systemctl disable "$broker_unit" 2>/dev/null || true
    fi
    if [ "$daemon_was_enabled" -eq 1 ]; then
      systemctl enable "$daemon_unit" 2>/dev/null || true
    else
      systemctl disable "$daemon_unit" 2>/dev/null || true
    fi
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
trap rollback EXIT HUP INT TERM

systemctl stop "$daemon_unit" "$broker_unit" 2>/dev/null || true
if [ -x /usr/bin/cockpit ]; then
  # Stop a legacy detached daemon too. An error aborts the install rather than
  # permitting two daemon authorities for the same uid.
  runuser -u "$daemon_user" -- /usr/bin/cockpit daemon stop --grace 30
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

stage_install cockpit /usr/bin/cockpit 0755
stage_install cockpit-containment-broker /usr/libexec/flycockpit/cockpit-containment-broker 0755
stage_install infra/systemd/cockpit-containment-broker@.service /usr/lib/systemd/system/cockpit-containment-broker@.service 0644
stage_install infra/systemd/cockpit-daemon@.service /usr/lib/systemd/system/cockpit-daemon@.service 0644
stage_install infra/tmpfiles.d/flycockpit-containment.conf /usr/lib/tmpfiles.d/flycockpit-containment.conf 0644

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
systemctl is-active --quiet "$broker_unit"
socket="/run/flycockpit/containment-broker-$daemon_uid.sock"
if [ "$(stat -c '%F:%u:%g:%a' "$socket")" != "socket:0:$daemon_gid:660" ]; then
  echo "containment broker did not publish the authenticated socket contract" >&2
  exit 1
fi
systemctl start "$daemon_unit"
systemctl is-active --quiet "$daemon_unit"
runuser -u "$daemon_user" -- /usr/bin/cockpit daemon status --json >/dev/null

committed=1
trap - EXIT HUP INT TERM
rm -rf "$transaction"
echo "Installed the FlyCockpit managed daemon and containment broker for $daemon_user (UID $daemon_uid)."
