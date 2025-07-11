/// DHCP option code for the DHCP message type option.
pub const DHCP_MESSAGE_TYPE_CODE: u8 = 53;
/// DHCP message type value for the DHCPOFFER message.
pub const DHCP_OFFER_VALUE: u8 = 2;
/// DHCP message type value for the DHCPACK message.
pub const DHCP_ACK_VALUE: u8 = 5;
/// DHCP message type value for the DHCPNAK message.
pub const DHCP_NAK_VALUE: u8 = 6;
/// DHCP option code for the IP address lease time.
pub const DHCP_LEASE_TIME_CODE: u8 = 51;
/// DHCP option code for the server identifier.
pub const DHCP_SERVER_IDENTIFIER_CODE: u8 = 54;
/// DHCP option code for the router (default gateway).
pub const DHCP_ROUTER_CODE: u8 = 3;
/// DHCP option code for the DNS servers.
pub const DHCP_DNS_CODE: u8 = 6;
/// DHCP option code for the subnet mask.
pub const DHCP_SUBNET_MASK_CODE: u8 = 1;
/// DHCP option code indicating the end of options.
pub const DHCP_END_CODE: u8 = 255;
/// DHCP option code for padding (no operation).
pub const DHCP_PAD_CODE: u8 = 0;

/// Size of the DHCP fixed header in bytes.
pub const DHCP_HEADER_SIZE: usize = 236;
/// Size of the DHCP magic cookie in bytes.
pub const DHCP_MAGIC_COOKIE_SIZE: usize = 4;
/// Size of the DHCP options field in bytes.
pub const DHCP_OPTIONS_SIZE: usize = 312;

/// DHCP magic cookie bytes that identify the DHCP options field.
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
