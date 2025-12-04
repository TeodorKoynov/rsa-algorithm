import random

def is_prime(n, k=5):
    """Пробабилистичен тест за простота на Милър-Рабин."""
    if n < 2:
        return False
    # Малки прости делители:
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Представяне на n-1 като (2^s)*d:
    s, d = 0, n-1
    while d % 2 == 0:
        s += 1
        d //= 2
    # Милър-Рабин тест k пъти:
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """Генерира случайно просто число с даден брой битове."""
    while True:
        # Генериране на случайно число с указаната дължина в битове
        candidate = random.getrandbits(bits)
        candidate |= 1  # правим го нечетно (последният бит 1)
        candidate |= (1 << bits-1)  # задаваме най-старшия бит, за да имаме точно 'bits' битово число
        if is_prime(candidate):
            return candidate

def gcd(a, b):
    """Най-голям общ делител (алгоритъм на Евклид)."""
    while b:
        a, b = b, a % b
    return abs(a)

def modinv(a, m):
    """Модуларен мултипликативен обратен на a по модул m (разширен алгоритъм на Евклид)."""
    # Разширен алгоритъм на Евклид за уравнението: a*x + m*y = gcd(a, m)
    orig_m = m
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    while m != 0:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    # Сега a = gcd(orig_a, orig_m), x0 е мултипликативният обратен на a мод orig_m ако gcd = 1
    if a != 1:
        raise Exception("Обратен елемент не съществува")
    else:
        return x0 % orig_m

def mod_exp(base, exp, mod):
    """Бързо повдигане на степен по модул (square-and-multiply)."""
    result = 1
    b = base % mod
    e = exp
    while e > 0:
        if e % 2 == 1:       # ако текущият бит на e е 1
            result = (result * b) % mod
        b = (b * b) % mod    # квадратиране
        e //= 2             # преминаване към следващия бит на експонентата
    return result

def generate_keys(bits=1024):
    """Генерира RSA ключове с дадена дължина (по подразбиране 1024 бита)."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # Често се използва фиксиран e = 65537, но се уверяваме, че е взаимно просто с phi_n
    e = 65537
    if gcd(e, phi_n) != 1:
        # ако 65537 не става (рядко), намираме друга подходяща стойност
        e = 3
        while gcd(e, phi_n) != 1:
            e += 2
    d = modinv(e, phi_n)
    return (n, e), (n, d)

def encrypt(message, pubkey):
    """RSA криптиране: връща списък от числови шифротекстове за всеки символ."""
    n, e = pubkey
    cipher_nums = []
    for ch in message:
        m = ord(ch)
        c = mod_exp(m, e, n)
        cipher_nums.append(c)
    return cipher_nums

def decrypt(cipher_nums, privkey):
    """RSA декриптиране: връща възстановения низ от списък числови шифротекстове."""
    n, d = privkey
    result = ""
    for c in cipher_nums:
        m = mod_exp(c, d, n)
        result += chr(m)
    return result

# Демонстрация на генериране на ключове и криптиране/декриптиране
pub, priv = generate_keys(bits=16)
print(f"Публичен ключ: (n={pub[0]}, e={pub[1]})")
print(f"Частен ключ: (n={priv[0]}, d={priv[1]})")
msg = "HELLO"
print(f"Оригинално съобщение: {msg}")
cipher = encrypt(msg, pub)
print("Шифровани данни:", cipher)
plain = decrypt(cipher, priv)
print("Дешифрирано съобщение:", plain)
