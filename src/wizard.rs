use crate::{config::Config, crypto::Crypto, device, types::Mode};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Password, Select};
use ring::aead;
use std::{collections::HashMap, fs, io, os::unix::fs::PermissionsExt, path::Path};

const MODE_SIMPLE: usize = 0;
const MODE_ADVANCED: usize = 1;
const MODE_EXPERT: usize = 2;

fn str_list(s: String) -> Vec<String> {
    if s.is_empty() {
        vec![]
    } else {
        s.split(',').map(|k| k.trim().to_string()).collect()
    }
}

fn str_opt(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn configure_connectivity(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode >= MODE_ADVANCED {
        config.listen =
            Input::with_theme(theme).with_prompt("Listen address").default(config.listen.clone()).interact_text()?;
    }
    config.peers = str_list(
        Input::with_theme(theme)
            .with_prompt("Peer addresses (comma separated)")
            .default(config.peers.join(","))
            .interact_text()?,
    );
    if mode >= MODE_ADVANCED {
        config.port_forwarding = Confirm::with_theme(theme)
            .with_prompt("Enable automatic port forwarding?")
            .default(config.port_forwarding)
            .interact()?;
    }
    if mode == MODE_EXPERT {
        config.advertise_addresses = str_list(
            Input::with_theme(theme)
                .with_prompt("Advertise addresses (comma separated)")
                .default(config.advertise_addresses.join(","))
                .interact_text()?,
        );
        config.peer_timeout = Input::with_theme(theme)
            .with_prompt("Peer timeout (in seconds)")
            .default(config.peer_timeout)
            .interact_text()?;
        let val = Input::with_theme(theme)
            .with_prompt("Keepalive interval (in seconds, 0 for default)")
            .default(config.keepalive.unwrap_or_default())
            .interact_text()?;
        config.keepalive = if val == 0 { None } else { Some(val) };
    }
    Ok(())
}

fn configure_crypto(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if (config.crypto.password.is_some() || config.crypto.private_key.is_some())
        && !Confirm::with_theme(theme).with_prompt("Create new crypto config?").default(false).interact()?
    {
        return Ok(());
    }
    let mut use_password = true;
    if mode >= MODE_ADVANCED {
        use_password = Select::with_theme(theme)
            .with_prompt("Crypto configuration method")
            .items(&["Simple (Password)", "Complex (Key pair)"])
            .default(if config.crypto.private_key.is_some() { 1 } else { 0 })
            .interact()?
            == 0
    }
    if use_password {
        config.crypto.password = Some(
            Password::with_theme(theme)
                .with_prompt("Password")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()?,
        );
        config.crypto.private_key = None;
        config.crypto.public_key = None;
        config.crypto.trusted_keys = vec![];
    } else {
        config.crypto.password = None;
        let (priv_key, pub_key) = match Select::with_theme(theme)
            .with_prompt("Specify key pair")
            .items(&["Generate new key pair", "Enter private key", "Generate from password"])
            .default(0)
            .interact()?
        {
            0 => {
                let (priv_key, pub_key) = Crypto::generate_keypair(None);
                info!("Private key: {}", priv_key);
                info!("Public key: {}", pub_key);
                (priv_key, pub_key)
            }
            1 => {
                let priv_key = Password::with_theme(theme)
                    .with_prompt("Private key")
                    .with_confirmation("Confirm private key", "Keys do not match")
                    .interact()?;
                let pub_key = try_fail!(Crypto::public_key_from_private_key(&priv_key), "Invalid private key: {:?}");
                info!("Public key: {}", pub_key);
                (priv_key, pub_key)
            }
            2 => {
                let password = Password::with_theme(theme)
                    .with_prompt("Password")
                    .with_confirmation("Confirm password", "Passwords do not match")
                    .interact()?;
                let (priv_key, pub_key) = Crypto::generate_keypair(Some(&password));
                info!("Private key: {}", priv_key);
                info!("Public key: {}", pub_key);
                (priv_key, pub_key)
            }
            _ => unreachable!(),
        };
        config.crypto.trusted_keys = str_list(
            Input::with_theme(theme)
                .with_prompt("Trusted keys (public keys, comma separated)")
                .default(pub_key.clone())
                .interact_text()?,
        );
        config.crypto.private_key = Some(priv_key);
        config.crypto.public_key = Some(pub_key);
    }
    if mode == MODE_EXPERT {
        let (unencrypted, allowed_algos) = Crypto::parse_algorithms(&config.crypto.algorithms)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid crypto algorithms"))?;
        let algos = MultiSelect::with_theme(theme)
            .with_prompt("Allowed encryption algorithms (select multiple)")
            .items_checked(&[
                ("Unencrypted (dangerous)", unencrypted),
                ("AES-128 in GCM mode", allowed_algos.contains(&&aead::AES_128_GCM)),
                ("AES-256 in GCM mode", allowed_algos.contains(&&aead::AES_256_GCM)),
                ("ChaCha20-Poly1305 (RFC 7539)", allowed_algos.contains(&&aead::CHACHA20_POLY1305)),
            ])
            .interact()?;
        config.crypto.algorithms = vec![];
        for (id, name) in &[(0, "PLAIN"), (1, "AES128"), (2, "AES256"), (3, "CHACHA20")] {
            if algos.contains(id) {
                config.crypto.algorithms.push(name.to_string());
            }
        }
    }
    Ok(())
}

fn configure_device(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode >= MODE_ADVANCED {
        config.device_type = match Select::with_theme(theme)
            .with_prompt("Device type")
            .items(&["Tun (IP based)", "Tap (Ethernet based)"])
            .default(if config.device_type == device::Type::Tun { 0 } else { 1 })
            .interact()?
        {
            0 => device::Type::Tun,
            1 => device::Type::Tap,
            _ => unreachable!(),
        }
    }
    if mode == MODE_EXPERT {
        config.device_name =
            Input::with_theme(theme).with_prompt("Device name").default(config.device_name.clone()).interact_text()?;
        config.device_path = str_opt(
            Input::with_theme(theme)
                .with_prompt("Device path (empty for default)")
                .default(config.device_path.as_ref().cloned().unwrap_or_default())
                .interact_text()?,
        );
        config.fix_rp_filter = Confirm::with_theme(theme)
            .with_prompt("Automatically fix insecure rp_filter settings")
            .default(config.fix_rp_filter)
            .interact()?;
        config.mode = match Select::with_theme(theme)
            .with_prompt("Operation mode")
            .items(&["Normal", "Router", "Switch", "Hub"])
            .default(match config.mode {
                Mode::Normal => 0,
                Mode::Router => 1,
                Mode::Switch => 2,
                Mode::Hub => 3,
            })
            .interact()?
        {
            0 => Mode::Normal,
            1 => Mode::Router,
            2 => Mode::Switch,
            3 => Mode::Hub,
            _ => unreachable!(),
        };
        if config.mode == Mode::Switch {
            config.switch_timeout = Input::with_theme(theme)
                .with_prompt("Switch timeout (in seconds")
                .default(config.switch_timeout)
                .interact_text()?;
        }
    }
    Ok(())
}

fn configure_addresses(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    config.ip = str_opt(
        Input::with_theme(theme)
            .with_prompt("Virtual IP address (e.g. 10.0.0.1, leave empty for none)")
            .allow_empty(true)
            .default(config.ip.as_ref().cloned().unwrap_or_default())
            .interact_text()?,
    );
    if config.device_type == device::Type::Tun {
        if mode >= MODE_ADVANCED {
            config.auto_claim = Confirm::with_theme(theme)
                .with_prompt("Automatically claim IP set on virtual interface?")
                .default(config.auto_claim)
                .interact()?;
        }
        if mode == MODE_EXPERT {
            config.claims = str_list(
                Input::with_theme(theme)
                    .with_prompt("Claim additional addresses (e.g. 10.0.0.0/24, comma separated, leave empty for none)")
                    .allow_empty(true)
                    .default(config.claims.join(","))
                    .interact_text()?,
            );
        }
    } else {
        config.claims = vec![];
    }
    if mode == MODE_EXPERT {
        config.ifup = str_opt(
            Input::with_theme(theme)
                .with_prompt("Interface setup command (leave empty for none)")
                .allow_empty(true)
                .default(config.ifup.as_ref().cloned().unwrap_or_default())
                .interact_text()?,
        );
        config.ifdown = str_opt(
            Input::with_theme(theme)
                .with_prompt("Interface tear down command (leave empty for none)")
                .allow_empty(true)
                .default(config.ifdown.as_ref().cloned().unwrap_or_default())
                .interact_text()?,
        );
    }
    Ok(())
}

fn configure_beacon(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode == MODE_EXPERT
        && Confirm::with_theme(theme)
            .with_prompt("Configure beacons?")
            .default(config.beacon_load.is_some() || config.beacon_store.is_some())
            .interact()?
    {
        config.beacon_store = match Select::with_theme(theme)
            .with_prompt("How to store beacons")
            .items(&["Do not store beacons", "Store to file", "Execute command"])
            .default(if let Some(v) = &config.beacon_store {
                if v.starts_with('|') {
                    2
                } else {
                    1
                }
            } else {
                0
            })
            .interact()?
        {
            0 => None,
            1 => Some(
                Input::with_theme(theme)
                    .with_prompt("File path")
                    .default(config.beacon_store.clone().unwrap_or_default())
                    .interact_text()?,
            ),
            2 => Some(format!(
                "|{}",
                Input::<String>::with_theme(theme)
                    .with_prompt("Command")
                    .default(config.beacon_store.clone().unwrap_or_default().trim_start_matches('|').to_string())
                    .interact_text()?
            )),
            _ => unreachable!(),
        };
        config.beacon_load = match Select::with_theme(theme)
            .with_prompt("How to load beacons")
            .items(&["Do not load beacons", "Load from file", "Execute command"])
            .default(if let Some(v) = &config.beacon_load {
                if v.starts_with('|') {
                    2
                } else {
                    1
                }
            } else {
                0
            })
            .interact()?
        {
            0 => None,
            1 => Some(
                Input::with_theme(theme)
                    .with_prompt("File path")
                    .default(config.beacon_load.clone().unwrap_or_default())
                    .interact_text()?,
            ),
            2 => Some(format!(
                "|{}",
                Input::<String>::with_theme(theme)
                    .with_prompt("Command")
                    .default(config.beacon_load.clone().unwrap_or_default().trim_start_matches('|').to_string())
                    .interact_text()?
            )),
            _ => unreachable!(),
        };
        config.beacon_interval = Input::with_theme(theme)
            .with_prompt("Beacon interval (in seconds)")
            .default(config.beacon_interval)
            .interact_text()?;
        config.beacon_password = str_opt(
            Password::with_theme(theme)
                .with_prompt("Beacon password (leave empty for none)")
                .with_confirmation("Confirm password", "Passwords do not match")
                .allow_empty_password(true)
                .interact()?,
        );
    }
    Ok(())
}

fn configure_stats(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode >= MODE_ADVANCED {
        config.stats_file = str_opt(
            Input::with_theme(theme)
                .with_prompt("Write stats to file (empty to disable)")
                .default(config.stats_file.clone().unwrap_or_default())
                .allow_empty(true)
                .interact_text()?,
        );
    }
    if mode == MODE_EXPERT {
        if Confirm::with_theme(theme)
            .with_prompt("Send statistics to statsd server?")
            .default(config.statsd_server.is_some())
            .interact()?
        {
            config.statsd_server = str_opt(
                Input::with_theme(theme)
                    .with_prompt("Statsd server URL")
                    .default(config.statsd_server.clone().unwrap_or_default())
                    .allow_empty(true)
                    .interact_text()?,
            );
            config.statsd_prefix = str_opt(
                Input::with_theme(theme)
                    .with_prompt("Statsd prefix")
                    .default(config.statsd_prefix.clone().unwrap_or_default())
                    .allow_empty(true)
                    .interact_text()?,
            );
        } else {
            config.statsd_server = None;
        }
    }
    Ok(())
}

fn configure_process(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode == MODE_EXPERT {
        config.user = str_opt(
            Input::with_theme(theme)
                .with_prompt("Run as different user (empty to disable)")
                .default(config.user.clone().unwrap_or_default())
                .allow_empty(true)
                .interact_text()?,
        );
        config.group = str_opt(
            Input::with_theme(theme)
                .with_prompt("Run as different group (empty to disable)")
                .default(config.group.clone().unwrap_or_default())
                .allow_empty(true)
                .interact_text()?,
        );
        config.pid_file = str_opt(
            Input::with_theme(theme)
                .with_prompt("Write process id to file (empty to disable)")
                .default(config.pid_file.clone().unwrap_or_default())
                .allow_empty(true)
                .interact_text()?,
        );
    }
    Ok(())
}

fn configure_hooks(config: &mut Config, mode: usize, theme: &ColorfulTheme) -> Result<(), io::Error> {
    if mode == MODE_EXPERT {
        if Confirm::with_theme(theme)
            .with_prompt("Set hooks to react on events?")
            .default(config.hook.is_some() || !config.hooks.is_empty())
            .interact()?
        {
            config.hook = str_opt(
                Input::with_theme(theme)
                    .with_prompt("Command to execute for all events (empty to disable)")
                    .default(config.hook.clone().unwrap_or_default())
                    .allow_empty(true)
                    .interact_text()?,
            );
            let mut hooks: HashMap<String, String> = Default::default();
            for event in &[
                "peer_connecting",
                "peer_connected",
                "peer_disconnected",
                "device_setup",
                "device_configured",
                "vpn_started",
                "vpn_shutdown",
            ] {
                if let Some(cmd) = str_opt(
                    Input::with_theme(theme)
                        .with_prompt(format!("Command to execute for event '{}' (empty to disable)", event))
                        .default(config.hooks.get(*event).cloned().unwrap_or_default())
                        .allow_empty(true)
                        .interact_text()?,
                ) {
                    hooks.insert(event.to_string(), cmd);
                }
            }
            config.hooks = hooks;
        } else {
            config.hook = None;
            config.hooks = Default::default();
        }
    }
    Ok(())
}

pub fn configure(name: Option<String>) -> Result<(), io::Error> {
    let theme = ColorfulTheme::default();

    let name = if let Some(name) = name {
        name
    } else {
        let mut names = vec![];
        for file in fs::read_dir("/etc/vpncloud")? {
            names.push(file?.path().file_stem().unwrap().to_str().unwrap().to_string());
        }
        let selection =
            Select::with_theme(&theme).with_prompt("Which network?").item("New network").items(&names).interact()?;
        if selection > 0 {
            names[selection - 1].clone()
        } else {
            Input::with_theme(&theme).with_prompt("Network name").interact_text()?
        }
    };

    let mut config = Config::default();
    let file = Path::new("/etc/vpncloud").join(format!("{}.net", name));
    if file.exists() {
        let f = fs::File::open(&file)?;
        let config_file = serde_yaml::from_reader(f)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse config file"))?;
        config.merge_file(config_file);
    }
    if file.parent().unwrap().metadata()?.permissions().readonly() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Config file not writable"));
    }

    loop {
        let mode = Select::with_theme(&theme)
            .with_prompt("Configuration mode")
            .items(&["Simple (minimal options)", "Advanced (some more options)", "Expert (all options)"])
            .default(MODE_SIMPLE)
            .interact()?;

        configure_connectivity(&mut config, mode, &theme)?;
        configure_crypto(&mut config, mode, &theme)?;
        configure_device(&mut config, mode, &theme)?;
        configure_addresses(&mut config, mode, &theme)?;
        configure_beacon(&mut config, mode, &theme)?;
        configure_stats(&mut config, mode, &theme)?;
        configure_process(&mut config, mode, &theme)?;
        configure_hooks(&mut config, mode, &theme)?;
        if Confirm::with_theme(&theme).with_prompt("Finish configuration?").default(true).interact()? {
            break;
        }
    }

    if Confirm::with_theme(&theme).with_prompt("Save config?").default(true).interact()? {
        let config_file = config.into_config_file();
        let f = fs::File::create(&file)?;
        serde_yaml::to_writer(f, &config_file)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse config file"))?;
        fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
        println!();
        println!("Use the following commands to control your VPN:");
        println!("  start the VPN:   sudo service vpncloud@{0} start", name);
        println!("  stop the VPN:    sudo service vpncloud@{0} stop", name);
        println!("  get the status:  sudo service vpncloud@{0} status", name);
        println!("  add VPN to autostart:       sudo systemctl enable vpncloud@{0}", name);
        println!("  remove VPN from autostart:  sudo systemctl disable vpncloud@{0}", name);
    }

    Ok(())
}
