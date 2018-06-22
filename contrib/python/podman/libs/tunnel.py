"""Cache for SSH tunnels."""
import collections
import os
import subprocess
import threading
import time
import weakref

Context = collections.namedtuple('Context', (
    'uri',
    'interface',
    'local_socket',
    'remote_socket',
    'username',
    'hostname',
    'identity_file',
))


class Portal(collections.MutableMapping):
    """Expiring container for tunnels."""

    def __init__(self, sweap=25):
        """Construct portal, reap tunnels every sweap seconds."""
        self.data = collections.OrderedDict()
        self.sweap = sweap
        self.ttl = sweap * 2
        self.lock = threading.RLock()

    def __getitem__(self, key):
        """Given uri return tunnel and update TTL."""
        with self.lock:
            value, _ = self.data[key]
            self.data[key] = (value, time.time() + self.ttl)
            self.data.move_to_end(key)
            return value

    def __setitem__(self, key, value):
        """Store given tunnel keyed with uri."""
        if not isinstance(value, Tunnel):
            raise ValueError('Portals only support Tunnels.')

        with self.lock:
            self.data[key] = (value, time.time() + self.ttl)
            self.data.move_to_end(key)

    def __delitem__(self, key):
        """Remove and close tunnel from portal."""
        with self.lock:
            value, _ = self.data[key]
            del self.data[key]
            value.close(key)
            del value

    def __iter__(self):
        """Iterate tunnels."""
        with self.lock:
            values = self.data.values()

        for tunnel, _ in values:
            yield tunnel

    def __len__(self):
        """Return number of tunnels in portal."""
        with self.lock:
            return len(self.data)

    def _schedule_reaper(self):
        timer = threading.Timer(interval=self.sweap, function=self.reap)
        timer.setName('PortalReaper')
        timer.setDaemon(True)
        timer.start()

    def reap(self):
        """Remove tunnels who's TTL has expired."""
        with self.lock:
            now = time.time()
            for entry, timeout in self.data:
                if timeout < now:
                    self.__delitem__(entry)
                else:
                    # StopIteration as soon as possible
                    break
            self._schedule_reaper()


class Tunnel(object):
    """SSH tunnel."""

    def __init__(self, context):
        """Construct Tunnel."""
        self.context = context
        self._tunnel = None

    def bore(self, id):
        """Create SSH tunnel from given context."""
        cmd = [
            'ssh',
            '-nNT',
            '-L',
            '{}:{}'.format(self.context.local_socket,
                           self.context.remote_socket),
            '-i',
            self.context.identity_file,
            'ssh://{}@{}'.format(self.context.username, self.context.hostname),
        ]

        if os.environ.get('PODMAN_DEBUG'):
            cmd.append('-vvv')

        self._tunnel = subprocess.Popen(cmd, close_fds=True)
        for i in range(5):
            if os.path.exists(self.context.local_socket):
                break
            time.sleep(1)
        else:
            raise TimeoutError('Failed to create tunnel using: {}'.format(
                ' '.join(cmd)))
        weakref.finalize(self, self.close, id)
        return self

    def close(self, id):
        """Close SSH tunnel."""
        print('Tunnel collapsed!')
        if self._tunnel is None:
            return

        self._tunnel.kill()
        self._tunnel.wait(300)
        os.remove(self.context.local_socket)
        self._tunnel = None
