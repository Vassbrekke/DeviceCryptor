//! Live FAT mount. Writes go into the volume at once. No copy-back on dismount.
//!
//! fatfs is not `Send`, so one worker thread owns the filesystem. FUSE calls
//! send it a job and wait.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use fatfs::{Dir, FileSystem, FsOptions};
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyWrite, Request,
};

use crate::cursor::VolumeCursor;
use crate::session::MountedVolume;
use crate::VolumeError;

const TTL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct Node {
    path: Vec<String>,
    is_dir: bool,
    size: u64,
}

type ListReply = Sender<Result<Vec<(String, bool, u64)>, Errno>>;

enum Job {
    Stat(Vec<String>, Sender<Result<(bool, u64), Errno>>),
    List(Vec<String>, ListReply),
    CreateFile(Vec<String>, String, Sender<Result<(), Errno>>),
    CreateDir(Vec<String>, String, Sender<Result<(), Errno>>),
    Remove(Vec<String>, String, Sender<Result<(), Errno>>),
    Read(Vec<String>, u64, u32, Sender<Result<Vec<u8>, Errno>>),
    Write(Vec<String>, u64, Vec<u8>, Sender<Result<u32, Errno>>),
}

struct Inodes {
    nodes: HashMap<INodeNo, Node>,
    by_path: HashMap<Vec<String>, INodeNo>,
    next_ino: u64,
    uid: u32,
    gid: u32,
}

pub struct FatFuse {
    tx: Sender<Job>,
    inodes: Mutex<Inodes>,
}

impl FatFuse {
    pub fn new(vol: Arc<Mutex<MountedVolume>>, protect: u64) -> Result<Self, VolumeError> {
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("dc-fat-fuse".into())
            .spawn(move || worker(vol, protect, rx, ready_tx))
            .map_err(VolumeError::Io)?;
        ready_rx
            .recv()
            .map_err(|e| VolumeError::Platform(e.to_string()))??;
        let mut inodes = Inodes {
            nodes: HashMap::new(),
            by_path: HashMap::new(),
            next_ino: 2,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        inodes.nodes.insert(
            INodeNo::ROOT,
            Node {
                path: Vec::new(),
                is_dir: true,
                size: 0,
            },
        );
        inodes.by_path.insert(Vec::new(), INodeNo::ROOT);
        Ok(Self {
            tx,
            inodes: Mutex::new(inodes),
        })
    }

    fn call<T>(&self, job: impl FnOnce(Sender<Result<T, Errno>>) -> Job) -> Result<T, Errno> {
        let (tx, rx) = mpsc::channel();
        self.tx.send(job(tx)).map_err(|_| Errno::EIO)?;
        rx.recv().map_err(|_| Errno::EIO)?
    }
}

impl Inodes {
    fn attr(&self, ino: INodeNo, node: &Node) -> FileAttr {
        FileAttr {
            ino,
            size: if node.is_dir { 0 } else { node.size },
            blocks: node.size.div_ceil(512),
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: if node.is_dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if node.is_dir { 0o755 } else { 0o644 },
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }

    fn intern(&mut self, path: Vec<String>, is_dir: bool, size: u64) -> INodeNo {
        if let Some(ino) = self.by_path.get(&path).copied() {
            if let Some(node) = self.nodes.get_mut(&ino) {
                node.is_dir = is_dir;
                node.size = size;
            }
            return ino;
        }
        let ino = INodeNo(self.next_ino);
        self.next_ino += 1;
        self.by_path.insert(path.clone(), ino);
        self.nodes.insert(ino, Node { path, is_dir, size });
        ino
    }

    fn forget_name(&mut self, parent: &[String], name: &str) {
        let mut path = parent.to_vec();
        path.push(name.to_string());
        if let Some(ino) = self.by_path.remove(&path) {
            self.nodes.remove(&ino);
        }
    }
}

fn io_errno(err: std::io::Error) -> Errno {
    match err.raw_os_error() {
        Some(libc::EINVAL) => Errno::EINVAL,
        Some(libc::EACCES) => Errno::EACCES,
        _ => Errno::EIO,
    }
}

fn at_dir<R>(
    dir: &Dir<'_, VolumeCursor>,
    comps: &[String],
    f: impl FnOnce(&Dir<'_, VolumeCursor>) -> Result<R, Errno>,
) -> Result<R, Errno> {
    if comps.is_empty() {
        return f(dir);
    }
    let child = dir.open_dir(&comps[0]).map_err(|_| Errno::ENOENT)?;
    at_dir(&child, &comps[1..], f)
}

fn stat_path(fs: &FileSystem<VolumeCursor>, path: &[String]) -> Result<(bool, u64), Errno> {
    if path.is_empty() {
        return Ok((true, 0));
    }
    let name = path.last().unwrap();
    let parent = &path[..path.len() - 1];
    let root = fs.root_dir();
    at_dir(&root, parent, |dir| {
        for entry in dir.iter() {
            let entry = entry.map_err(|_| Errno::EIO)?;
            if entry.file_name() == *name {
                return Ok((entry.is_dir(), entry.len()));
            }
        }
        Err(Errno::ENOENT)
    })
}

fn worker(
    vol: Arc<Mutex<MountedVolume>>,
    protect: u64,
    rx: Receiver<Job>,
    ready: Sender<Result<(), VolumeError>>,
) {
    let cursor = {
        let c = VolumeCursor::new(vol);
        if protect > 0 {
            c.with_hidden_protection(protect)
        } else {
            c
        }
    };
    let fs = match FileSystem::new(cursor, FsOptions::new()) {
        Ok(fs) => fs,
        Err(e) => {
            let _ = ready.send(Err(VolumeError::Format(e.to_string())));
            return;
        }
    };
    let _ = ready.send(Ok(()));
    while let Ok(job) = rx.recv() {
        match job {
            Job::Stat(path, reply) => {
                let _ = reply.send(stat_path(&fs, &path));
            }
            Job::List(path, reply) => {
                let root = fs.root_dir();
                let listed = at_dir(&root, &path, |dir| {
                    let mut out = Vec::new();
                    for entry in dir.iter() {
                        let entry = entry.map_err(|_| Errno::EIO)?;
                        let name = entry.file_name();
                        if name == "." || name == ".." {
                            continue;
                        }
                        out.push((name, entry.is_dir(), entry.len()));
                    }
                    Ok(out)
                });
                let _ = reply.send(listed);
            }
            Job::CreateFile(parent, name, reply) => {
                let root = fs.root_dir();
                let made = at_dir(&root, &parent, |dir| {
                    if stat_name(dir, &name).is_ok() {
                        dir.remove(&name).map_err(|_| Errno::EIO)?;
                    }
                    dir.create_file(&name).map(|_| ()).map_err(|_| Errno::EIO)
                });
                let _ = reply.send(made);
            }
            Job::CreateDir(parent, name, reply) => {
                let root = fs.root_dir();
                let made = at_dir(&root, &parent, |dir| {
                    dir.create_dir(&name).map(|_| ()).map_err(|_| Errno::EIO)
                });
                let _ = reply.send(made);
            }
            Job::Remove(parent, name, reply) => {
                let root = fs.root_dir();
                let removed = at_dir(&root, &parent, |dir| {
                    dir.remove(&name).map_err(|_| Errno::EIO)
                });
                let _ = reply.send(removed);
            }
            Job::Read(path, offset, size, reply) => {
                let name = path.last().cloned().unwrap_or_default();
                let parent = path[..path.len().saturating_sub(1)].to_vec();
                let root = fs.root_dir();
                let got = at_dir(&root, &parent, |dir| {
                    let mut file = dir.open_file(&name).map_err(|_| Errno::ENOENT)?;
                    file.seek(SeekFrom::Start(offset)).map_err(io_errno)?;
                    let mut buf = vec![0u8; size as usize];
                    let n = file.read(&mut buf).map_err(io_errno)?;
                    buf.truncate(n);
                    Ok(buf)
                });
                let _ = reply.send(got);
            }
            Job::Write(path, offset, data, reply) => {
                let name = path.last().cloned().unwrap_or_default();
                let parent = path[..path.len().saturating_sub(1)].to_vec();
                let root = fs.root_dir();
                let wrote = at_dir(&root, &parent, |dir| {
                    let mut file = dir.open_file(&name).map_err(|_| Errno::ENOENT)?;
                    file.seek(SeekFrom::Start(offset)).map_err(io_errno)?;
                    file.write_all(&data).map_err(io_errno)?;
                    file.flush().map_err(io_errno)?;
                    Ok(data.len() as u32)
                });
                let _ = reply.send(wrote);
            }
        }
    }
}

fn stat_name(dir: &Dir<'_, VolumeCursor>, name: &str) -> Result<(), Errno> {
    for entry in dir.iter() {
        let entry = entry.map_err(|_| Errno::EIO)?;
        if entry.file_name() == name {
            return Ok(());
        }
    }
    Err(Errno::ENOENT)
}

impl Filesystem for FatFuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let mut g = self.inodes.lock().unwrap();
        let Some(parent_node) = g.nodes.get(&parent).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !parent_node.is_dir {
            reply.error(Errno::ENOTDIR);
            return;
        }
        let name = name.to_string_lossy().to_string();
        let mut path = parent_node.path.clone();
        path.push(name);
        match self.call(|tx| Job::Stat(path.clone(), tx)) {
            Ok((is_dir, size)) => {
                let ino = g.intern(path, is_dir, size);
                let node = g.nodes.get(&ino).unwrap().clone();
                let attr = g.attr(ino, &node);
                reply.entry(&TTL, &attr, Generation(0));
            }
            Err(code) => reply.error(code),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let mut g = self.inodes.lock().unwrap();
        let Some(node) = g.nodes.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Ok((is_dir, size)) = self.call(|tx| Job::Stat(node.path.clone(), tx)) {
            if let Some(n) = g.nodes.get_mut(&ino) {
                n.is_dir = is_dir;
                n.size = size;
            }
        }
        let node = g.nodes.get(&ino).unwrap().clone();
        let attr = g.attr(ino, &node);
        reply.attr(&TTL, &attr);
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let mut g = self.inodes.lock().unwrap();
        let Some(parent_node) = g.nodes.get(&parent).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().to_string();
        if let Err(code) =
            self.call(|tx| Job::CreateDir(parent_node.path.clone(), name.clone(), tx))
        {
            reply.error(code);
            return;
        }
        let mut path = parent_node.path;
        path.push(name);
        let ino = g.intern(path, true, 0);
        let node = g.nodes.get(&ino).unwrap().clone();
        let attr = g.attr(ino, &node);
        reply.entry(&TTL, &attr, Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let mut g = self.inodes.lock().unwrap();
        let Some(parent_node) = g.nodes.get(&parent).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().to_string();
        if let Err(code) = self.call(|tx| Job::Remove(parent_node.path.clone(), name.clone(), tx)) {
            reply.error(code);
            return;
        }
        g.forget_name(&parent_node.path, &name);
        reply.ok();
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut g = self.inodes.lock().unwrap();
        let Some(parent_node) = g.nodes.get(&parent).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        let name = name.to_string_lossy().to_string();
        if let Err(code) =
            self.call(|tx| Job::CreateFile(parent_node.path.clone(), name.clone(), tx))
        {
            reply.error(code);
            return;
        }
        let mut path = parent_node.path;
        path.push(name);
        let ino = g.intern(path, false, 0);
        let node = g.nodes.get(&ino).unwrap().clone();
        let attr = g.attr(ino, &node);
        reply.created(
            &TTL,
            &attr,
            Generation(0),
            FileHandle(ino.0),
            FopenFlags::empty(),
        );
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let g = self.inodes.lock().unwrap();
        let Some(node) = g.nodes.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if node.is_dir {
            reply.error(Errno::EISDIR);
            return;
        }
        match self.call(|tx| Job::Read(node.path, offset, size, tx)) {
            Ok(buf) => reply.data(&buf),
            Err(code) => reply.error(code),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut g = self.inodes.lock().unwrap();
        let Some(node) = g.nodes.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.call(|tx| Job::Write(node.path.clone(), offset, data.to_vec(), tx)) {
            Ok(n) => {
                if let Some(nnode) = g.nodes.get_mut(&ino) {
                    nnode.size = nnode.size.max(offset + data.len() as u64);
                }
                reply.written(n);
            }
            Err(code) => reply.error(code),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let mut g = self.inodes.lock().unwrap();
        let Some(node) = g.nodes.get(&ino).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !node.is_dir {
            reply.error(Errno::ENOTDIR);
            return;
        }
        let listed = match self.call(|tx| Job::List(node.path.clone(), tx)) {
            Ok(v) => v,
            Err(code) => {
                reply.error(code);
                return;
            }
        };
        let mut rows = vec![
            (ino, FileType::Directory, ".".to_string()),
            (INodeNo::ROOT, FileType::Directory, "..".to_string()),
        ];
        for (name, is_dir, size) in listed {
            let mut path = node.path.clone();
            path.push(name.clone());
            let child = g.intern(path, is_dir, size);
            rows.push((
                child,
                if is_dir {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                },
                name,
            ));
        }
        for (i, (child, kind, name)) in rows.into_iter().enumerate().skip(offset as usize) {
            if reply.add(child, (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

/// Mount and return a handle. Dropping the handle unmounts.
pub fn spawn_live(
    vol: Arc<Mutex<MountedVolume>>,
    protect: u64,
    mountpoint: &Path,
) -> Result<fuser::BackgroundSession, VolumeError> {
    let fs = FatFuse::new(vol, protect)?;
    let mut config = Config::default();
    config
        .mount_options
        .push(MountOption::FSName("devicecryptor".into()));
    fuser::spawn_mount(fs, mountpoint, &config).map_err(|e| VolumeError::Platform(e.to_string()))
}

static LIVE: std::sync::LazyLock<Mutex<HashMap<String, fuser::BackgroundSession>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn keep_live(id: &str, session: fuser::BackgroundSession) {
    LIVE.lock().unwrap().insert(id.to_string(), session);
}

pub fn drop_live(id: &str) {
    LIVE.lock().unwrap().remove(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cursor::format_fat32;
    use crate::session::{create_container, open_container, CreateOptions, OpenOptions};
    use std::fs;

    #[test]
    fn live_write_lands_in_the_volume() {
        let dir = tempfile::tempdir().unwrap();
        let container = dir.path().join("vol.dc");
        let mountpoint = dir.path().join("mnt");
        fs::create_dir(&mountpoint).unwrap();
        create_container(
            &container,
            &CreateOptions {
                password: b"live-pass",
                size: 16 * 1024 * 1024,
                sparse: true,
                ..CreateOptions::default()
            },
        )
        .unwrap();
        let open = OpenOptions {
            password: b"live-pass",
            keyfiles: &[],
            pim: 0,
            prf: None,
            protect_hidden: false,
            hidden_password: None,
        };
        {
            let vol = Arc::new(Mutex::new(open_container(&container, &open).unwrap()));
            format_fat32(Arc::clone(&vol)).unwrap();
        }
        let vol = Arc::new(Mutex::new(open_container(&container, &open).unwrap()));
        let session = spawn_live(vol, 0, &mountpoint).unwrap();
        let mounted = (0..50).any(|_| {
            let text = fs::read_to_string("/proc/mounts").unwrap_or_default();
            if text.contains(&mountpoint.display().to_string()) {
                true
            } else {
                std::thread::sleep(Duration::from_millis(100));
                false
            }
        });
        assert!(mounted, "live mount did not appear");
        fs::write(mountpoint.join("HELLO.TXT"), b"live-write").unwrap();
        drop(session);
        std::thread::sleep(Duration::from_millis(200));

        let vol = Arc::new(Mutex::new(open_container(&container, &open).unwrap()));
        let cursor = VolumeCursor::new(vol);
        let fs = FileSystem::new(cursor, FsOptions::new()).unwrap();
        let mut file = fs.root_dir().open_file("HELLO.TXT").unwrap();
        let mut got = String::new();
        file.read_to_string(&mut got).unwrap();
        assert_eq!(got, "live-write");
    }
}
