// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2020  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#include <stdint.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>

int32_t setup_device(int32_t fd, char *ifname, int32_t flags) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) return 1;
  strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
  return 0;
}

int32_t setup_tap_device(int32_t fd, char *ifname) {
  return setup_device(fd, ifname, IFF_TAP | IFF_NO_PI);
}

int32_t setup_tun_device(int32_t fd, char *ifname) {
  return setup_device(fd, ifname, IFF_TUN | IFF_NO_PI);
}
