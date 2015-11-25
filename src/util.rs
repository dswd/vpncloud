use std::{mem, slice};

#[inline(always)]
pub unsafe fn as_bytes<T>(obj: &T) -> &[u8] {
    slice::from_raw_parts(mem::transmute::<&T, *const u8>(obj), mem::size_of::<T>())
}

#[inline(always)]
pub unsafe fn as_obj<T>(data: &[u8]) -> &T {
    assert!(data.len() >= mem::size_of::<T>());
    mem::transmute(data.as_ptr())
}

macro_rules! fail {
    ($format:expr) => ( {
        use std::process;
        error!($format);
        process::exit(-1);
    } );
    ($format:expr, $( $arg:expr ),+) => ( {
        use std::process;
        error!($format, $( $arg ),+ );
        process::exit(-1);
    } );
}

macro_rules! try_fail {
    ($val:expr, $format:expr) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, err)
        }
    } );
    ($val:expr, $format:expr, $( $arg:expr ),+) => ( {
        match $val {
            Ok(val) => val,
            Err(err) => fail!($format, $( $arg ),+, err)
        }
    } );
}
