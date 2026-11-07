mod serve;
mod wire;

pub use serve::{
    CloseDurability, EjectBarrier, PrepareOutcome, PrepareVerdict, SessionEnd, SessionParams,
    serve_connection,
};
pub use wire::{
    ATTR_LEN, INTERFACE_VERSION, MAX_BODY, Request, eject, op, put_attr, put_bytes, read_request,
    request_flags, setattr_mask, status, status_of, take_bytes, write_response,
};

#[cfg(test)]
mod tests;
