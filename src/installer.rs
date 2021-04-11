use crate::{error::Error, util::run_cmd};
use std::{
    env,
    fs::{self, File},
    io::Write,
    os::unix::fs::PermissionsExt,
    process::Command,
};

const MANPAGE: &[u8] = include_bytes!("../target/vpncloud.1.gz");
const SERVICE_FILE: &[u8] = include_bytes!("../assets/vpncloud@.service");
const TARGET_FILE: &[u8] = include_bytes!("../assets/vpncloud.target");
const WS_PROXY_SERVICE_FILE: &[u8] = include_bytes!("../assets/vpncloud-wsproxy.service");
const EXAMPLE_CONFIG: &[u8] = include_bytes!("../assets/example.net.disabled");

fn systemctl_daemon_reload() {
    let mut cmd = Command::new("systemctl");
    cmd.arg("daemon-reload");
    run_cmd(cmd);
}

pub fn install() -> Result<(), Error> {
    env::current_exe()
        .and_then(|p| fs::copy(p, "/usr/bin/vpncloud"))
        .map_err(|e| Error::FileIo("Failed to copy binary", e))?;
    fs::set_permissions("/usr/bin/vpncloud", fs::Permissions::from_mode(0o755))
        .map_err(|e| Error::FileIo("Failed to set permissions for binary", e))?;
    fs::create_dir_all("/etc/vpncloud").map_err(|e| Error::FileIo("Failed to create config folder", e))?;
    fs::set_permissions("/etc/vpncloud", fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::FileIo("Failed to set permissions for config folder", e))?;
    File::create("/etc/vpncloud/example.net.disabled")
        .and_then(|mut f| f.write_all(EXAMPLE_CONFIG))
        .map_err(|e| Error::FileIo("Failed to create example config", e))?;
    File::create("/usr/share/man/man1/vpncloud.1.gz")
        .and_then(|mut f| f.write_all(MANPAGE))
        .map_err(|e| Error::FileIo("Failed to create manpage", e))?;
    File::create("/lib/systemd/system/vpncloud@.service")
        .and_then(|mut f| f.write_all(SERVICE_FILE))
        .map_err(|e| Error::FileIo("Failed to create service file", e))?;
    File::create("/lib/systemd/system/vpncloud.target")
        .and_then(|mut f| f.write_all(TARGET_FILE))
        .map_err(|e| Error::FileIo("Failed to create service target file", e))?;
    File::create("/lib/systemd/system/vpncloud-wsproxy.service")
        .and_then(|mut f| f.write_all(WS_PROXY_SERVICE_FILE))
        .map_err(|e| Error::FileIo("Failed to create wsporxy service file", e))?;
    systemctl_daemon_reload();
    info!("Install successful");
    Ok(())
}

pub fn uninstall() -> Result<(), Error> {
    fs::remove_file("/etc/vpncloud/example.net.disabled").map_err(|e| Error::FileIo("Failed to remove binary", e))?;
    fs::remove_file("/usr/share/man/man1/vpncloud.1.gz").map_err(|e| Error::FileIo("Failed to remove manpage", e))?;
    fs::remove_file("/lib/systemd/system/vpncloud@.service")
        .map_err(|e| Error::FileIo("Failed to remove service file", e))?;
    fs::remove_file("/lib/systemd/system/vpncloud.target")
        .map_err(|e| Error::FileIo("Failed to remove service target file", e))?;
    fs::remove_file("/lib/systemd/system/vpncloud-wsproxy.service")
        .map_err(|e| Error::FileIo("Failed to remove wsproxy service file", e))?;
    fs::remove_file("/usr/bin/vpncloud").map_err(|e| Error::FileIo("Failed to remove binary", e))?;
    systemctl_daemon_reload();
    info!("Uninstall successful");
    Ok(())
}
