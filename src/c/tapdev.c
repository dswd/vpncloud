#include <stdint.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>

int32_t setup_tap_device(int32_t fd, char *ifname) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) return 1;
  strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
  return 0;
}