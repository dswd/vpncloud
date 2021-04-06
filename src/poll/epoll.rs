// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2021  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

use std::{io, os::unix::io::RawFd};

use super::WaitResult;

pub struct EpollWait {
    poll_fd: RawFd,
    event: libc::epoll_event,
    socket: RawFd,
    device: RawFd,
    timeout: u32,
}

impl EpollWait {
    pub fn new(socket: RawFd, device: RawFd, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, libc::EPOLLIN as u32)
    }

    pub fn testing(socket: RawFd, device: RawFd, timeout: u32) -> io::Result<Self> {
        Self::create(socket, device, timeout, (libc::EPOLLIN | libc::EPOLLOUT) as u32)
    }

    fn create(socket: RawFd, device: RawFd, timeout: u32, flags: u32) -> io::Result<Self> {
        let mut event = libc::epoll_event { u64: 0, events: 0 };
        let poll_fd = unsafe { libc::epoll_create(3) };
        if poll_fd == -1 {
            return Err(io::Error::last_os_error());
        }
        for fd in &[socket, device] {
            event.u64 = *fd as u64;
            event.events = flags;
            let res = unsafe { libc::epoll_ctl(poll_fd, libc::EPOLL_CTL_ADD, *fd, &mut event) };
            if res == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self { poll_fd, event, socket, device, timeout })
    }
}

impl Drop for EpollWait {
    fn drop(&mut self) {
        unsafe { libc::close(self.poll_fd) };
    }
}

impl Iterator for EpollWait {
    type Item = WaitResult;

    fn next(&mut self) -> Option<Self::Item> {
        Some(match unsafe { libc::epoll_wait(self.poll_fd, &mut self.event, 1, self.timeout as i32) } {
            -1 => WaitResult::Error(io::Error::last_os_error()),
            0 => WaitResult::Timeout,
            1 => {
                if self.event.u64 == self.socket as u64 {
                    WaitResult::Socket
                } else if self.event.u64 == self.device as u64 {
                    WaitResult::Device
                } else {
                    unreachable!()
                }
            }
            _ => unreachable!(),
        })
    }
}
