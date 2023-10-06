#[macro_use]
mod util {
    include!("../src/util.rs");
}
mod error {
    include!("../src/error.rs");
}
mod payload {
    include!("../src/payload.rs");
}
mod types {
    include!("../src/types.rs");
}
mod table {
    include!("../src/table.rs");
}
mod engine {
    pub mod common {
        include!("../src/engine/common.rs");
    }
    pub mod coms {
        include!("../src/engine/coms.rs");
    }
    mod shared {
        include!("../src/engine/shared.rs");
    }
    mod device_thread {
        include!("../src/engine/device_thread.rs");
    }
    mod socket_thread {
        include!("../src/engine/socket_thread.rs");
    }
    mod housekeep_thread {
        include!("../src/engine/housekeep_thread.rs");
    }
    mod extras_thread {
        include!("../src/engine/extras_thread.rs");
    }
}
mod config {
    include!("../src/config.rs");
}
mod device {
    include!("../src/device.rs");
}
mod net {
    include!("../src/net.rs");
}
mod beacon {
    include!("../src/beacon.rs");
}
mod messages {
    include!("../src/messages.rs");
}
mod port_forwarding {
    include!("../src/port_forwarding.rs");
}
mod traffic {
    include!("../src/traffic.rs");
}
mod poll {
    pub mod epoll{
        include!("../src/poll/epoll.rs");
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub use self::epoll::EpollWait as WaitImpl;

    use std::io;

    pub enum WaitResult {
        Timeout,
        Socket,
        Device,
        Error(io::Error)
    }
}
mod crypto {
    pub mod core {
        include!("../src/crypto/core.rs");
    }
    pub mod init {
        include!("../src/crypto/init.rs");
    }
    pub mod rotate {
        include!("../src/crypto/rotate.rs");
    }
    pub mod common {
        include!("../src/crypto/common.rs");
    }
    pub use common::*;
    pub use self::core::{EXTRA_LEN, TAG_LEN};
}
mod tests {
    pub mod common {
        include!("../src/tests/common.rs");
    }
}
