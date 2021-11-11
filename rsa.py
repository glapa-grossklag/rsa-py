#!/usr/bin/env python3

from dataclasses import dataclass
from random import randrange as uniform


# ------------------------------------------------------------------------------
# Math
# ------------------------------------------------------------------------------


def __is_even(n: int) -> bool:
    return n % 2 == 0


def __is_odd(n: int) -> bool:
    return n % 2 != 0


def __is_prime(n: int) -> bool:
    # TODO: Go faster.
    if n < 2:
        return False

    if n == 2:
        return True

    if __is_even(n):
        return False

    for divisor in range(3, n, 2):
        if n % divisor == 0:
            return False

    return True


def __gcd(a: int, b: int) -> int:
    """
    Return the greatest common denominator of `a` and `b`.
    """
    while b != 0:
        a, b = b, a % b
    return a


def __lcm(a: int, b: int) -> int:
    """
    Return the least common multiple of `a` and `b`.
    """
    return (a * b) // __gcd(a, b)


def __inverse(a: int, n: int):
    """
    Return the multiplicative inverse of a (mod n).
    """
    r, r_prime = n, a
    t, t_prime = 0, 1
    while r_prime != 0:
        q = r // r_prime
        r, r_prime = r_prime, r - q * r_prime
        t, t_prime = t_prime, t - q * t_prime
    if r > 1:
        raise Exception
    elif t < 0:
        return t + n
    else:
        return t


def __power_mod(a: int, b: int, n: int) -> int:
    """
    Return a to the power of b (mod n).
    """
    v = 1
    p = a
    while b > 0:
        if __is_odd(b):
            v = (v * p) % n
        p = (p ** 2) % n
        b //= 2
    return v


def __make_random_prime(lower: int, upper: int) -> int:
    p = 0
    while not __is_prime(p):
        p = uniform(lower, upper)
    return p


# ------------------------------------------------------------------------------
# RSA
# ------------------------------------------------------------------------------


@dataclass
class PublicKey:
    e: int
    n: int


@dataclass
class PrivateKey:
    d: int
    n: int


def make_key_pair(bits: int) -> tuple[PublicKey, PrivateKey]:
    # Create two large primes, p and q.
    lower = 2 ** (bits // 2 - 1)
    upper = 2 ** (bits // 2) - 1
    p = __make_random_prime(lower, upper)
    q = __make_random_prime(lower, upper)
    while q == p:
        q = __make_random_prime(lower, upper)

    λ = __lcm(p - 1, q - 1)

    e = 65537
    d = __inverse(e, λ)
    n = p * q

    return (PublicKey(e, n), PrivateKey(d, n))


def encrypt(m: int, public: PublicKey) -> int:
    return __power_mod(m, public.e, public.n)


def decrypt(c: int, public: PublicKey, private: PrivateKey) -> int:
    return __power_mod(c, private.d, public.n)
