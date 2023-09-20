use clap::Parser;
#[cfg(not(target_env = "musl"))]
use libc::c_ulong;
use std::fs;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

use linux_raw_sys::general::fsxattr;
use linux_raw_sys::ioctl;

extern "C" {
    fn strverscmp(cs: *const i8, ct: *const i8) -> i32;
}

#[allow(dead_code)]
#[allow(nonstandard_style)]
mod dqblk_xfs_binding;
#[allow(dead_code)]
#[allow(nonstandard_style)]
mod dqblk_xfs_util;
#[allow(dead_code)]
#[allow(nonstandard_style)]
mod quota_binding;

#[allow(nonstandard_style)]
#[inline]
pub const fn QCMD(cmd: u32, type_: u32) -> u32 {
    (cmd << quota_binding::SUBCMDSHIFT) | (type_ & quota_binding::SUBCMDMASK)
}

#[derive(Parser, Debug)]
#[command(author="zhang_syi@qq.com", version="0.0.1", about="Get xfs directory info", long_about = None)]
struct Args {
    /// Name of directory
    #[arg(short, long)]
    dir: String,

    /// Block device
    #[arg(short, long)]
    block: String,
}

fn main() {
    let args = Args::parse();

    let path = Path::new(&args.dir);
    if !path.is_dir() {
        println!("{} is not directory", path.display());
        return;
    }
    // println!("{}", path.is_dir());

    let f = File::open(path).unwrap();
    // println!("fd:{}", f.as_raw_fd());
    let fd = f.as_raw_fd();

    // let attr = fsxattr{
    //     ..Default::default()
    // };

    let attr = fsxattr {
        fsx_xflags: 0,
        fsx_extsize: 0,
        fsx_nextents: 0,
        fsx_projid: 0,
        fsx_cowextsize: 0,
        fsx_pad: [0, 0, 0, 0, 0, 0, 0, 0],
    };

    #[cfg(target_env = "musl")]
    let ret = unsafe { libc::ioctl(fd, ioctl::FS_IOC_FSGETXATTR as i32, &attr) };
    #[cfg(not(target_env = "musl"))]
    let ret = unsafe { libc::ioctl(fd, ioctl::FS_IOC_FSGETXATTR as c_ulong, &attr) };
    if ret < 0 {
        println!("libc::ioctl failed:{}", ret);
        return;
    }
    println!("{} fsx_projid:{}", path.display(), attr.fsx_projid);

    let mut kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    kernel.pop();
    let min_version = String::from("4.6.0");
    let ret = unsafe {
        strverscmp(
            kernel.as_ptr() as *const i8,
            min_version.as_ptr() as *const i8,
        )
    };
    if ret < 0 {
        println!("linux kernel:{kernel} less than {min_version} may not support Q_XGETNEXTQUOTA");
    }

    let cmd = QCMD(dqblk_xfs_util::Q_XGETNEXTQUOTA, quota_binding::PRJQUOTA);
    let mut id = 0;
    loop {
        // let mut quota: dqblk_xfs_binding::fs_disk_quota = unsafe { mem::zeroed() };
        let mut quota = dqblk_xfs_binding::fs_disk_quota {
            ..Default::default()
        };
        let ret = unsafe {
            libc::quotactl(
                cmd as i32,
                args.block.as_ptr() as *const i8,
                id,
                &mut quota as *mut dqblk_xfs_binding::fs_disk_quota as *mut i8,
            )
        };
        if ret < 0 {
            break;
        }
        id = quota.d_id as i32 + 1;
        println!(
            "{} d_id:{:<5} d_blk_hardlimit:{}",
            args.block, quota.d_id, quota.d_blk_hardlimit
        );
    }
}
