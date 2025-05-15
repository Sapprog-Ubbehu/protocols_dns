import socket
import threading
import pickle
import time
from dns import message, query, exception, rdatatype

CACHE_FILE = 'dns_cache.bin'
UPSTREAM_DNS = ('8.8.8.8', 53)
GC_INTERVAL = 10


class DnsCache:
    def __init__(self):
        self.lock = threading.Lock()
        try:
            with open(CACHE_FILE, 'rb') as f:
                self.store = pickle.load(f)
        except Exception:
            self.store = {}

    def save(self):
        with self.lock:
            with open(CACHE_FILE, 'wb') as f:
                pickle.dump(self.store, f)

    def get(self, name, rdtype, rdclass):
        key = (name.to_text(), rdtype, rdclass)
        now = time.time()
        results = []
        with self.lock:
            entries = self.store.get(key, [])
            for rrset, expire in entries:
                if expire > now:
                    ttl = int(expire - now)
                    results.append((rrset, ttl))
            self.store[key] = [(rr, exp) for rr, exp in entries if exp > now]
        return results

    def put(self, rrset):
        name = rrset.name.to_text()
        key = (name, rrset.rdtype, rrset.rdclass)
        expire = time.time() + rrset.ttl
        with self.lock:
            self.store.setdefault(key, [])
            self.store[key].append((rrset, expire))

    def gc(self):
        while True:
            now = time.time()
            with self.lock:
                for key in list(self.store):
                    self.store[key] = [(rr, exp) for rr, exp in self.store[key] if exp > now]
                    if not self.store[key]:
                        del self.store[key]
            time.sleep(GC_INTERVAL)


cache = DnsCache()
threading.Thread(target=cache.gc, daemon=True).start()


def handle_query(data, addr, sock):
    try:
        req = message.from_wire(data)
        q = req.question[0]
        name, rdtype, rdclass = q.name, q.rdtype, q.rdclass
        resp = message.make_response(req)
        entries = cache.get(name, rdtype, rdclass)
        if entries:
            for rrset, ttl in entries:
                rs_copy = rrset.copy()
                rs_copy.ttl = ttl
                resp.answer.append(rs_copy)
        else:
            try:
                upstream_resp = query.udp(req, UPSTREAM_DNS, timeout=2)
                for section in (upstream_resp.answer, upstream_resp.authority, upstream_resp.additional):
                    for rrset in section:
                        cache.put(rrset)
                resp = upstream_resp
            except exception.Timeout:
                resp.set_rcode(2)
        sock.sendto(resp.to_wire(), addr)
    except Exception:
        pass


if __name__ == '__main__':
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(('', 53))
    print('DNS caching server listening on port 53...')
    try:
        while True:
            data, addr = srv.recvfrom(512)
            threading.Thread(target=handle_query, args=(data, addr, srv), daemon=True).start()
    except KeyboardInterrupt:
        print('Shutting down, saving cache...')
        cache.save()
