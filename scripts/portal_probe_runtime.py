"""Runtime helpers shared by the local captive-portal probes."""

import os
import pwd


def drop_privileges_after_bind():
    """Drop root after binding a privileged port, if started through sudo."""
    if os.geteuid() != 0:
        return

    try:
        uid = int(os.environ["SUDO_UID"])
        gid = int(os.environ["SUDO_GID"])
        sudo_user = os.environ["SUDO_USER"]
    except (KeyError, ValueError) as exc:
        raise RuntimeError(
            "refusing to serve HTTP as root; launch through sudo from a user account"
        ) from exc

    if uid <= 0:
        raise RuntimeError("refusing to serve HTTP as root")

    account = pwd.getpwuid(uid)
    if account.pw_name != sudo_user or account.pw_gid != gid:
        raise RuntimeError("sudo user identity did not match the account database")

    os.initgroups(account.pw_name, gid)
    os.setgid(gid)
    os.setuid(uid)
