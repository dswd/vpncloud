macro_rules! assert_clean {
    ($($node: expr),*) => {
        $(
        assert_eq!($node.socket4().pop_outbound().map(|(addr, mut msg)| (addr, $node.decode_message(&mut msg).unwrap().without_data())), None);
        assert_eq!($node.socket6().pop_outbound().map(|(addr, mut msg)| (addr, $node.decode_message(&mut msg).unwrap().without_data())), None);
        assert_eq!($node.device().pop_outbound(), None);
        )*
    };
}

macro_rules! assert_message4 {
    ($from: expr, $from_addr: expr, $to: expr, $to_addr: expr, $message: expr) => {
        let (addr, mut data) = msg4_get(&mut $from);
        assert_eq!($to_addr, addr);
        {
            let message = $from.decode_message(&mut data).unwrap();
            assert_eq!($message, message.without_data());
        }
        msg4_put(&mut $to, $from_addr, data);
    };
}

#[allow(unused_macros)]
macro_rules! assert_message6 {
    ($from: expr, $from_addr: expr, $to: expr, $to_addr: expr, $message: expr) => {
        let (addr, mut data) = msg6_get(&mut $from);
        assert_eq!($to_addr, addr);
        {
            let message = $from.decode_message(&mut data).unwrap();
            assert_eq!($message, message.without_data());
        }
        msg6_put(&mut $to, $from_addr, data);
    };
}

macro_rules! simulate {
    ($($node: expr => $addr: expr),*) => {
        simulate(&mut [$((&mut $node, $addr)),*]);
    };
}

macro_rules! simulate_time {
    ($time:expr, $($node: expr => $addr: expr),*) => {
        for _ in 0..$time {
            use crate::util::{MockTimeSource, TimeSource};
            MockTimeSource::set_time(MockTimeSource::now()+1);
            $(
                $node.trigger_housekeep();
            )*
            simulate(&mut [$((&mut $node, $addr)),*]);
        }
    };
}


macro_rules! assert_connected {
    ($($node:expr),*) => {
        for node1 in [$(&$node),*].iter() {
            for node2 in [$(&$node),*].iter() {
                if node1.node_id() == node2.node_id() {
                    continue
                }
                assert!(node1.peers().contains_node(&node2.node_id()));
            }
        }
    };
}
