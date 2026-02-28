class CurveFp:
    def __init__(self, p, a, b, order=None):
        self.p = p
        self.a = a
        self.b = b
        self.order = order

    def contains_point(self, x, y):
        # y^2 = x^3 + a*x + b
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0


class PointJacobi:
    def __init__(self, curve, x, y, z, order=None):
        self.curve = curve
        self.x = x
        self.y = y
        self.z = z
        self.order = order

    def to_affine(self):
        if self.z == 0:
            return None # INFINITY
        z_inv = pow(self.z, self.curve.p - 2, self.curve.p)
        z_inv2 = (z_inv * z_inv) % self.curve.p
        z_inv3 = (z_inv2 * z_inv) % self.curve.p
        return ((self.x * z_inv2) % self.curve.p, (self.y * z_inv3) % self.curve.p)

    def __add__(self, other):
        if self.z == 0:
            return other
        if other.z == 0:
            return self

        p = self.curve.p
        u1 = (self.x * other.z ** 2) % p
        u2 = (other.x * self.z ** 2) % p
        s1 = (self.y * other.z ** 3) % p
        s2 = (other.y * self.z ** 3) % p

        if u1 == u2:
            if s1 != s2:
                return PointJacobi(self.curve, 0, 1, 0)
            return self.double()

        h = (u2 - u1) % p
        r = (s2 - s1) % p
        h2 = (h * h) % p
        h3 = (h2 * h) % p
        v = (u1 * h2) % p

        x3 = (r * r - h3 - 2 * v) % p
        y3 = (r * (v - x3) - s1 * h3) % p
        z3 = (self.z * other.z * h) % p
        return PointJacobi(self.curve, x3, y3, z3)

    def double(self):
        if self.z == 0:
            return self

        p = self.curve.p
        y2 = (self.y * self.y) % p
        s = (4 * self.x * y2) % p
        m = (3 * self.x * self.x + self.curve.a * self.z ** 4) % p
        x3 = (m * m - 2 * s) % p
        y3 = (m * (s - x3) - 8 * y2 * y2) % p
        z3 = (2 * self.y * self.z) % p
        return PointJacobi(self.curve, x3, y3, z3)

    def __mul__(self, scalar):
        res = PointJacobi(self.curve, 0, 1, 0) # INFINITY
        addend = self
        k = scalar
        while k > 0:
            if k & 1:
                res = res + addend
            addend = addend.double()
            k >>= 1
        return res

INFINITY = None
