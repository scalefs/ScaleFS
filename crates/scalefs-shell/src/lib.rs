pub mod outcome;
pub mod toast;

#[cfg(windows)]
pub mod announce;
#[cfg(windows)]
mod com;
#[cfg(windows)]
mod eject;
#[cfg(windows)]
mod ffi;
#[cfg(windows)]
mod notice;
#[cfg(windows)]
pub mod register;
#[cfg(windows)]
mod text;
