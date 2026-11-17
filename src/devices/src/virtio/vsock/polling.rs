// SPDX-License-Identifier: Apache-2.0

use super::muxer::ProxyMap;
use super::proxy::ProxyRawHandle;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

/// Apply an update only while its proxy still owns the socket handle.
///
/// Event processing releases the proxy lock before applying removals. In that
/// gap another thread can remove the proxy and reuse its descriptor for a new
/// connection. A delayed poll deletion must never target that new connection.
pub(super) fn update_live_polling(
    proxies: &ProxyMap,
    epoll: &Epoll,
    id: u64,
    fd: ProxyRawHandle,
    events: EventSet,
) {
    let proxies = proxies.read().unwrap();
    let Some(proxy) = proxies.get(&id) else {
        return;
    };
    let proxy = proxy.lock().unwrap();
    if proxy.poll_handle() != fd {
        return;
    }
    // Keep both guards until the complete delete/add pair has finished:
    // removal needs the map write lock, and peer updates need the proxy lock.
    let _ = epoll.ctl(ControlOperation::Delete, fd, &EpollEvent::default());
    if !events.is_empty() {
        let _ = epoll.ctl(ControlOperation::Add, fd, &EpollEvent::new(events, id));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::virtio::vsock::proxy::Proxy;
    use crate::virtio::vsock::unix::UnixAcceptorProxy;
    use std::collections::HashMap;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex, RwLock};

    #[test]
    fn a_removed_proxy_cannot_delete_a_new_connections_readiness() {
        let path = std::env::temp_dir().join(format!("kp-{}", rand::random::<u64>()));
        let proxy = UnixAcceptorProxy::new(2, &path, 1000).unwrap();
        let fd = proxy.poll_handle();
        let proxies: ProxyMap = Arc::new(RwLock::new(HashMap::from([(
            2,
            Mutex::new(Box::new(proxy) as Box<dyn Proxy>),
        )])));
        let mut epoll = Epoll::new().unwrap();
        update_live_polling(&proxies, &epoll, 2, fd, EventSet::IN);
        let _client = UnixStream::connect(&path).unwrap();

        // This is the exact late-update state after descriptor reuse: proxy 1
        // is gone, but its old fd is already registered for live proxy 2.
        update_live_polling(&proxies, &epoll, 1, fd, EventSet::empty());
        let mut events = [EpollEvent::default(); 1];
        assert_eq!(epoll.wait(1, 1000, &mut events).unwrap(), 1);
        assert_eq!(events[0].data(), 2);

        // The live owner must still be able to remove its own registration.
        update_live_polling(&proxies, &epoll, 2, fd, EventSet::empty());
        assert_eq!(epoll.wait(1, 0, &mut events).unwrap(), 0);
        drop(proxies);
        std::fs::remove_file(path).unwrap();
    }
}
