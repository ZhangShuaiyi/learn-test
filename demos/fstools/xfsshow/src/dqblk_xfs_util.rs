/// note: forms first QCMD argument
#[inline]
pub const fn XQM_CMD(x: u32) -> u32 {
    (('X' as u32) << 8) + (x)
}

/// test if for XFS
#[inline]
pub const fn XQM_COMMAND(x: u32) -> bool {
    (x & (0xff << 8)) == (('X' as u32) << 8)
}

/// enable accounting/enforcement
pub const Q_XQUOTAON: u32 = XQM_CMD(1);
/// disable accounting/enforcement
pub const Q_XQUOTAOFF: u32 = XQM_CMD(2);
/// get disk limits and usage
pub const Q_XGETQUOTA: u32 = XQM_CMD(3);
/// set disk limits
pub const Q_XSETQLIM: u32 = XQM_CMD(4);
/// get quota subsystem status
pub const Q_XGETQSTAT: u32 = XQM_CMD(5);
/// free disk space used by dquots
pub const Q_XQUOTARM: u32 = XQM_CMD(6);
/// delalloc flush, updates dquots
pub const Q_XQUOTASYNC: u32 = XQM_CMD(7);
/// newer version of get quota
pub const Q_XGETQSTATV: u32 = XQM_CMD(8);
/// get disk limits and usage >= ID
pub const Q_XGETNEXTQUOTA: u32 = XQM_CMD(9);
