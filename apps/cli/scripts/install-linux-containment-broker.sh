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
systemctl stop "cockpit-daemon@$daemon_uid.service" 2>/dev/null || true
systemctl stop "cockpit-containment-broker@$daemon_uid.service" 2>/dev/null || true
install -d -m 0755 /etc/flycockpit /usr/libexec/flycockpit /usr/lib/systemd/system /usr/lib/tmpfiles.d
install -m 0755 cockpit /usr/bin/cockpit
install -m 0755 cockpit-containment-broker /usr/libexec/flycockpit/cockpit-containment-broker
install -m 0644 infra/systemd/cockpit-containment-broker@.service /usr/lib/systemd/system/cockpit-containment-broker@.service
install -m 0644 infra/systemd/cockpit-daemon@.service /usr/lib/systemd/system/cockpit-daemon@.service
install -m 0644 infra/tmpfiles.d/flycockpit-containment.conf /usr/lib/tmpfiles.d/flycockpit-containment.conf

capability=/etc/flycockpit/containment-capability-$daemon_uid
if [ ! -e "$capability" ]; then
  umask 077
  dd if=/dev/urandom of="$capability" bs=32 count=1 status=none
fi
chown root:root "$capability"
chmod 0400 "$capability"

systemd-tmpfiles --create flycockpit-containment.conf
systemctl daemon-reload
systemctl enable "cockpit-containment-broker@$daemon_uid.service" "cockpit-daemon@$daemon_uid.service"
systemctl start "cockpit-containment-broker@$daemon_uid.service"
systemctl start "cockpit-daemon@$daemon_uid.service"

echo "Installed the FlyCockpit managed daemon and containment broker for $daemon_user (UID $daemon_uid)."
