use super::wire::{AttrOut, EntryOut, OpenOut, SetattrIn, StatfsOut, errno};

pub trait Filesystem {
    fn getattr(&self, nodeid: u64) -> Result<AttrOut, i32>;
    fn lookup(&self, parent: u64, name: &[u8]) -> Result<EntryOut, i32>;
    fn readdir(&self, nodeid: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32>;
    fn open(&self, nodeid: u64, flags: u32) -> Result<OpenOut, i32>;
    fn read(&self, nodeid: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32>;
    fn release(&self, nodeid: u64, fh: u64);
    fn statfs(&self) -> Result<StatfsOut, i32>;

    fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, i32> {
        let _ = nodeid;
        Err(errno::ENOSYS)
    }

    fn setattr(&self, nodeid: u64, change: &SetattrIn) -> Result<AttrOut, i32> {
        let _ = (nodeid, change);
        Err(errno::EROFS)
    }

    fn mkdir(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        let _ = (parent, name, mode, uid, gid);
        Err(errno::EROFS)
    }

    fn symlink(
        &self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        let _ = (parent, name, target, uid, gid);
        Err(errno::EROFS)
    }

    fn mknod(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> Result<EntryOut, i32> {
        let _ = (parent, name, mode, rdev, uid, gid);
        Err(errno::EROFS)
    }

    fn link(&self, source: u64, new_parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
        let _ = (source, new_parent, name);
        Err(errno::EROFS)
    }

    fn setxattr(&self, inode: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i32> {
        let _ = (inode, name, value, flags);
        Err(errno::EROFS)
    }

    fn getxattr(&self, inode: u64, name: &[u8]) -> Result<Vec<u8>, i32> {
        let _ = (inode, name);
        Err(errno::ENODATA)
    }

    fn listxattr(&self, inode: u64) -> Result<Vec<u8>, i32> {
        let _ = inode;
        Ok(Vec::new())
    }

    fn removexattr(&self, inode: u64, name: &[u8]) -> Result<(), i32> {
        let _ = (inode, name);
        Err(errno::EROFS)
    }

    fn create(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(EntryOut, OpenOut), i32> {
        let _ = (parent, name, mode, uid, gid);
        Err(errno::EROFS)
    }

    fn write(&self, nodeid: u64, fh: u64, offset: u64, data: &[u8]) -> Result<u32, i32> {
        let _ = (nodeid, fh, offset, data);
        Err(errno::EROFS)
    }

    fn unlink(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
        let _ = (parent, name);
        Err(errno::EROFS)
    }

    fn rmdir(&self, parent: u64, name: &[u8]) -> Result<(), i32> {
        let _ = (parent, name);
        Err(errno::EROFS)
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        replace: bool,
    ) -> Result<(), i32> {
        let _ = (old_parent, old_name, new_parent, new_name, replace);
        Err(errno::EROFS)
    }

    fn flush(&self, nodeid: u64, fh: u64) -> Result<(), i32> {
        let _ = (nodeid, fh);
        Ok(())
    }

    fn fsync(&self, nodeid: u64, fh: u64, datasync: bool) -> Result<(), i32> {
        let _ = (nodeid, fh, datasync);
        Ok(())
    }
}
