# VpnCloud for Windows

## Toolchain

rustup target add x86_64-pc-windows-gnu
rustup toolchain install stable-x86_64-pc-windows-gnu
apt-get install mingw64

## Problems

### Running VpnCloud

**Problem:**

- Library "daemonize" does not compile
  - Windows uses "Services" instead of daemonized processes
- Library "privdrop" does not compile
  - Is dropping privileges in Windows services even a thing?
- Library "signal" does not compile
  - Windows services work differently, no Ctrl-C handling needed
- Normal Windows programs can't stay active when the user logs out

**Potential solution:**

- Wrap VpnCloud as Windows service
  - https://github.com/mullvad/windows-service-rs
- Do not support dropping privileges under Windows

### Polling solution

**Problem:**

- Epoll is Linux only
- RawFd is Unix only

**Potential solution:**

Use multi-threading to remove the need to wait on multiple events at the same time:

- One thread waits on the device and sends to the socket
- One thread waits on the socket and sends to the device and handles the control traffic

Problems to solve:

- Synchronization is slow
  - Do not use locking in hot code, cache shared data locally and synchronize periodically

### Tun/Tap devices

**Problem:**

Tun/Tap works completely different on Windows

- Drivers need to be signed by Microsoft, complicated process

**Potential solution:**

Use existing Tun & Tap drivers:

- (Old) TapWindows from OpenVPN project
  - https://community.openvpn.net/openvpn/wiki/GettingTapWindows
  - https://github.com/Tazdevil971/tap-windows

- (New) WinTun from Wireguard
  - https://www.wintun.net/

### Configuration

**Problem:**

- Windows users are not used to write config files and execute commands
- Windows setup is more complicated than in Linux (install Drivers, register Services, etc.)

**Potential solution:**

- Create configuration UI
