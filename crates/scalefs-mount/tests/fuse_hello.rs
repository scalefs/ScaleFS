
#![cfg(target_os = "linux")]

use scalefs_mount::fuse::device::FuseMount;
use scalefs_mount::fuse::fs::Filesystem;
use scalefs_mount::fuse::session::serve;
use scalefs_mount::fuse::wire::{
    Attr, AttrOut, EntryOut, OpenOut, StatfsOut, dirent_type, errno, push_dirent,
};

const HELLO: &[u8] = b"Hello from ScaleFS!\n";

struct HelloFs;

fn root_attr() -> Attr {
    Attr {
        ino: 1,
        mode: 0o040755,
        nlink: 2,
        blksize: 4096,
        ..Attr::default()
    }
}

fn file_attr() -> Attr {
    Attr {
        ino: 2,
        size: HELLO.len() as u64,
        blocks: 1,
        mode: 0o100644,
        nlink: 1,
        blksize: 4096,
        ..Attr::default()
    }
}

impl Filesystem for HelloFs {
    fn getattr(&self, nodeid: u64) -> Result<AttrOut, i32> {
        let attr = match nodeid {
            1 => root_attr(),
            2 => file_attr(),
            _ => return Err(errno::ENOENT),
        };
        Ok(AttrOut {
            attr_valid: 1,
            attr_valid_nsec: 0,
            attr,
        })
    }

    fn lookup(&self, parent: u64, name: &[u8]) -> Result<EntryOut, i32> {
        if parent != 1 || name != b"hello.txt" {
            return Err(errno::ENOENT);
        }
        Ok(EntryOut {
            nodeid: 2,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: file_attr(),
        })
    }

    fn readdir(&self, nodeid: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        if nodeid != 1 {
            return Err(errno::ENOTDIR);
        }
        let mut out = Vec::new();
        let capacity = size as usize;
        let entries: [(u64, u32, &[u8]); 3] = [
            (1, dirent_type::DIRECTORY, b"."),
            (1, dirent_type::DIRECTORY, b".."),
            (2, dirent_type::REGULAR, b"hello.txt"),
        ];
        for (index, (ino, kind, name)) in entries.iter().enumerate() {
            let position = index as u64 + 1;
            if position <= offset {
                continue;
            }
            if !push_dirent(&mut out, capacity, *ino, position, *kind, name) {
                break;
            }
        }
        Ok(out)
    }

    fn open(&self, nodeid: u64, _flags: u32) -> Result<OpenOut, i32> {
        match nodeid {
            1 | 2 => Ok(OpenOut {
                fh: nodeid,
                open_flags: 0,
            }),
            _ => Err(errno::ENOENT),
        }
    }

    fn read(&self, nodeid: u64, _fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, i32> {
        if nodeid != 2 {
            return Err(errno::EINVAL);
        }
        let start = (offset as usize).min(HELLO.len());
        let end = (start + size as usize).min(HELLO.len());
        Ok(HELLO[start..end].to_vec())
    }

    fn release(&self, _nodeid: u64, _fh: u64) {}

    fn statfs(&self) -> Result<StatfsOut, i32> {
        Ok(StatfsOut {
            blocks: 1,
            files: 2,
            bsize: 4096,
            namelen: 255,
            frsize: 4096,
            ..StatfsOut::default()
        })
    }
}

#[test]
fn hello_filesystem_serves_through_the_kernel() {
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse absent");
        return;
    }
    let mountpoint = std::env::temp_dir().join(format!("scalefs-fuse-{}", std::process::id()));
    std::fs::create_dir_all(&mountpoint).unwrap();

    let mut mount = match FuseMount::mount(&mountpoint, false) {
        Ok(mount) => mount,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: mounting needs root ({error})");
            let _ = std::fs::remove_dir_all(&mountpoint);
            return;
        }
        Err(error) => panic!("mount failed: {error}"),
    };

    let client_path = mountpoint.clone();
    let client = std::thread::spawn(move || {
        let names: Vec<String> = std::fs::read_dir(&client_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["hello.txt".to_string()]);

        let file = client_path.join("hello.txt");
        let metadata = std::fs::metadata(&file).unwrap();
        assert_eq!(metadata.len(), HELLO.len() as u64);
        assert!(metadata.is_file());

        let content = std::fs::read(&file).unwrap();
        assert_eq!(content, HELLO);

        assert!(std::fs::metadata(client_path.join("missing")).is_err());
    });

    let server = std::thread::spawn(move || {
        let filesystem = HelloFs;
        let _ = serve(&mount, &filesystem, 1);
        mount.unmount();
    });

    client.join().expect("client assertions hold");
    scalefs_mount::fuse::device::detach_mountpoint(&mountpoint).unwrap();
    server.join().expect("serve loop ends after unmount");
    let _ = std::fs::remove_dir_all(&mountpoint);
}

#[test]
fn parallel_clients_over_a_multithreaded_loop() {
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("skipping: /dev/fuse absent");
        return;
    }
    let mountpoint = std::env::temp_dir().join(format!("scalefs-fuse-mt-{}", std::process::id()));
    std::fs::create_dir_all(&mountpoint).unwrap();

    let mut mount = match FuseMount::mount(&mountpoint, false) {
        Ok(mount) => mount,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: mounting needs root ({error})");
            let _ = std::fs::remove_dir_all(&mountpoint);
            return;
        }
        Err(error) => panic!("mount failed: {error}"),
    };

    let clients: Vec<_> = (0..4)
        .map(|_| {
            let path = mountpoint.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let content = std::fs::read(path.join("hello.txt")).unwrap();
                    assert_eq!(content, HELLO);
                    let metadata = std::fs::metadata(path.join("hello.txt")).unwrap();
                    assert_eq!(metadata.len(), HELLO.len() as u64);
                    let count = std::fs::read_dir(&path).unwrap().count();
                    assert_eq!(count, 1);
                }
            })
        })
        .collect();

    let server = std::thread::spawn(move || {
        let filesystem = HelloFs;
        let _ = serve(&mount, &filesystem, 4);
        mount.unmount();
    });

    for client in clients {
        client.join().expect("client assertions hold");
    }
    scalefs_mount::fuse::device::detach_mountpoint(&mountpoint).unwrap();
    server.join().expect("all workers end after unmount");
    let _ = std::fs::remove_dir_all(&mountpoint);
}
