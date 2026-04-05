#![no_std]
use aya_tool::pod;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ForwardRule {
    pub target_ip: [u8; 4],
    pub target_port: u16,
    pub action: u32,
    pub packets: u64,
    pub bytes: u64,
}


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InterfaceState {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ForwardRule {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for InterfaceState {}