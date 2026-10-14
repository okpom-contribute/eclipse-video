import base64
import hashlib
import json
import secrets
import threading
import time

TOKEN_KEY = bytes.fromhex('1b272f05e1e0fc6d43f8b86cf8f1e9c1a14a1fd7c7ef0304508e308735b5ba0b')
TOKEN_SKEW = 600
LIFETIME = 1800

P = 2**255-19
Q = 2**252+27742317777372353535851937790883648493
D = -121665*pow(121666, P-2, P) % P
ROOT = pow(2, (P-1)//4, P)


class AccessError(ValueError):
    pass


def _point_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    first = (y1-x1)*(y2-x2) % P
    second = (y1+x1)*(y2+x2) % P
    third = t1*2*D*t2 % P
    fourth = z1*2*z2 % P
    e, f, g, h = second-first, fourth-third, fourth+third, second+first
    return (e*f % P, g*h % P, f*g % P, e*h % P)


def _point_mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(a, b):
    return (a[0]*b[2]-b[0]*a[2]) % P == 0 and (a[1]*b[2]-b[1]*a[2]) % P == 0


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, 'little')
    sign = y >> 255
    y &= (1 << 255)-1
    if y >= P:
        return None
    x2 = (y*y-1)*pow(D*y*y+1, P-2, P) % P
    if x2 == 0:
        return None if sign else (0, y, 1, 0)
    x = pow(x2, (P+3)//8, P)
    if (x*x-x2) % P:
        x = x*ROOT % P
    if (x*x-x2) % P:
        return None
    if x & 1 != sign:
        x = P-x
    return (x, y, 1, x*y % P)


BASE = _decompress((4*pow(5, P-2, P) % P).to_bytes(32, 'little'))


def ed25519_verify(public, message, signature):
    if len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32]+public+message).digest(), 'little') % Q
    return _point_equal(_point_mul(s, BASE), _point_add(r, _point_mul(h, a)))


def _unpad(text):
    return base64.urlsafe_b64decode(text+'='*(-len(text) % 4))


def verify_build_token(token, now=None):
    if not isinstance(token, str) or len(token) > 512:
        raise AccessError('Update to the latest build of Eclipse Animator to continue.')
    parts = token.split('.')
    if len(parts) != 3 or parts[0] != 'v1':
        raise AccessError('Update to the latest build of Eclipse Animator to continue.')
    try:
        payload = json.loads(_unpad(parts[1]))
        signature = _unpad(parts[2])
    except (ValueError, UnicodeError):
        raise AccessError('Update to the latest build of Eclipse Animator to continue.') from None
    if not ed25519_verify(TOKEN_KEY, (parts[0]+'.'+parts[1]).encode(), signature):
        raise AccessError('This Eclipse Animator build could not be verified. Reinstall the latest version.')
    if not isinstance(payload, dict) or payload.get('v') != 1:
        raise AccessError('This Eclipse Animator build could not be verified. Reinstall the latest version.')
    build = payload.get('b')
    if isinstance(build, bool) or not isinstance(build, int):
        raise AccessError('This Eclipse Animator build could not be verified. Reinstall the latest version.')
    expires = payload.get('e')
    if isinstance(expires, bool) or not isinstance(expires, (int, float)):
        raise AccessError('This Eclipse Animator build could not be verified. Reinstall the latest version.')
    if (time.time() if now is None else now) > expires+TOKEN_SKEW:
        raise AccessError('Update to the latest build of Eclipse Animator to continue.')
    return build


class AccessGate:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._grants = {}
        self.last_error = ''

    def _prune(self, now):
        self._grants = {ticket: row for ticket, row in self._grants.items() if row[0] > now}

    def authorize(self, data):
        try:
            result = self._authorize(data)
        except AccessError as error:
            self.last_error = str(error)
            raise
        self.last_error = ''
        return result

    def _grant(self, fingerprint, now):
        self._prune(now)
        if len(self._grants) >= 16:
            oldest = min(self._grants, key=lambda ticket: self._grants[ticket][0])
            del self._grants[oldest]
        ticket = secrets.token_urlsafe(32)
        self._grants[ticket] = (now + LIFETIME, fingerprint)
        return {'ticket': ticket, 'expiresIn': LIFETIME}

    def _authorize(self, data):
        token = data.get('token') if isinstance(data, dict) else None
        verify_build_token(token)
        with self._lock:
            return self._grant(hashlib.sha256(token.encode()).digest(), self._clock())

    def allowed(self, ticket):
        if not isinstance(ticket, str) or len(ticket) > 128:
            return False
        row = self._grants.get(ticket)
        return row is not None and row[0] > self._clock()

    def clear(self):
        with self._lock:
            self._grants.clear()
