from functools import reduce
import random


# CBC mode AES-192
class AES:

    def __init__(self, key, iv=None):

        self.state = None

        key = AES.check_bytes(key, "key", lambda n: n == 24)
        self.key = self.expand_key(key)

        iv = AES.check_bytes(iv, "IV", lambda n: n == 16)
        self.iv = iv

    def encrypt(self, ptext):
        # return ciphertext as a byte-like array
        # check whether image is multiple of 16
        check = AES.text_check
        ptext = AES.check_bytes(ptext, "plaintext", check)
        return self.process_blocks(ptext)

    def decrypt(self, ctext):
        # return plain text as a byte-like array
        check, inverse = AES.text_check, True
        ctext = AES.check_bytes(ctext, "ciphertext", check)
        return self.process_blocks(ctext, inverse=inverse)

    def process_blocks(self, text, inverse=False):
        result, mode_block, cbc_block = bytearray(), None, None

        mode_block = self.iv

        # separate the plain text or ciphertext to blocks where each block consists of 16 bytes
        for count, i in enumerate(range(0, len(text), 16)):
            block = text[i: i + 16]

        # AES first process
        #     if it is encryption, then need to run the XOR key function
            if not inverse:
                block = AES.xor_blocks(block, mode_block)
            else:
                cbc_block = block

            result_block = self.process_block(block, inverse)

            if not inverse:
                mode_block = result_block
            else:
                result_block = AES.xor_blocks(result_block, mode_block)
                mode_block = cbc_block

            result.extend(result_block)
        return bytes(result)

    def process_block(self, block, inverse=False):
        rounds = len(self.key)

        # Set state vector from current block in column-initial order.
        self.state = []

        for i in range(4):
            self.state.append([block[i], block[i + 4], block[i + 8], block[i + 12]])

        # Round keys could be applied in either order.
        if not inverse:
            initial, start, end, step = 0, 1, rounds - 1, 1
        else:
            initial, start, end, step = rounds - 1, rounds - 2, 0, -1

        # Initial round key addition.
        self.add_round_key(initial)

        for repeat_round in range(start, end, step):
            if not inverse:
                self.sub_bytes()
                self.shift_rows()
                self.mix_columns()
                self.add_round_key(repeat_round)
            else:
                self.shift_rows(inverse=True)
                self.sub_bytes(inverse=True)
                self.add_round_key(repeat_round)
                self.mix_columns(inverse=True)

        # Final round (do not need the mix column process).
        if not inverse:
            self.sub_bytes()
            self.shift_rows()
        else:
            self.shift_rows(inverse=True)
            self.sub_bytes(inverse=True)
        self.add_round_key(end)

        # Undo the column-initial transposition in the state vector.
        return b"".join(bytes(self.state_column(col)) for col in range(4))

    @staticmethod
    def mul(p1: int, p2: int):
        # multiplies binary polynomials in Galois field(2 ** 8).
        result = 0

        # Algebraic expansion is followed by modular reduction.
        for exp in range(0, p2.bit_length() + 1):
            if p2 & (1 << exp):
                result ^= p1 << exp

        while result.bit_length() > 8:
            result ^= AES.m_x << (result.bit_length() - 9)

        return result

    # AES second process
    def sub_bytes(self, inverse=False):
        s_box = AES.s_box if not inverse else AES.inv_s_box
        for i in range(4):
            for j in range(4):
                self.state[i][j] = s_box[self.state[i][j]]

    # AES third process
    def shift_rows(self, inverse=False):
        for row in range(1, 4):
            self.state[row] = AES.rotate(self.state[row], row if not inverse else -row)

    # AES fourth process
    def mix_columns(self, inverse=False):
        # Perform matrix multiplication on each column in the state vector.
        if not inverse:
            matrix = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        else:
            matrix = [
                [14, 11, 13, 9],
                [9, 14, 11, 13],
                [13, 9, 14, 11],
                [11, 13, 9, 14],
            ]

        for i in range(4):
            col, new_col = self.state_column(i), []

            for j in range(4):
                terms = (AES.mul(x, y) for x, y in zip(col, matrix[j]))
                new_col.append(reduce(lambda a, b: a ^ b, terms))

            self.set_state_column(i, new_col)

    # AES fifth process
    def add_round_key(self, rnd):
        for i in range(4):
            for j in range(4):
                self.state[i][j] ^= self.key[rnd][i][j]

    # AES subprocess to expand key for add round key process
    @staticmethod
    def expand_key(key):
        # The current round of key expansion.
        i = 0

        # The first n bytes of the expanded key are simply the encryption key.
        key, n = list(key), len(key)

        # Expand the key to at least b bytes.
        b = 208

        while len(key) < b:
            i += 1

            t, p = key[-4:], key[-n: -n + 4]
            t = [AES.s_box[i] for i in AES.rotate(t, 1)]
            t[0] ^= AES.rcon[i]
            key.extend(tb ^ pb for tb, pb in zip(t, p))

            for _ in range(3):
                t, p = key[-4:], key[-n: -n + 4]
                key.extend(tb ^ pb for tb, pb in zip(t, p))

            if n == 32:
                t, p = key[-4:], key[-n: -n + 4]
                t = [AES.s_box[i] for i in t]
                key.extend(tb ^ pb for tb, pb in zip(t, p))

            if n == 16:
                continue

            for _ in range(2 if n == 24 else 3):
                t, p = key[-4:], key[-n: -n + 4]
                key.extend(tb ^ pb for tb, pb in zip(t, p))

        # Turn the expanded key into a series of 4x4 arrays, transposing
        # each block to allow direct 1:1 XOR during AddRoundKey().
        key = [
            tuple(
                zip(
                    *[
                        key[i: i + 4],
                        key[i + 4: i + 8],
                        key[i + 8: i + 12],
                        key[i + 12: i + 16],
                    ]
                )
            )
            for i in range(0, b, 16)
        ]

        # The final result is arbitrarily a list of tuples of tuples.
        return key

    @staticmethod
    def rotate(lst, rotate=1):
        return lst[rotate:] + lst[:rotate]

    def state_column(self, col):
        return [self.state[row][col] for row in range(4)]

    def set_state_column(self, col, new_col):
        for row in range(len(new_col)):
            self.state[row][col] = new_col[row]

    # add padding to last block of the plaintext to make each block has a same size
    def add_padding(bs):
        letters = bytes(chr(random.randint(1, 31)), 'utf-8')
        extra = len(bs) % 16
        if extra > 0:
            bs += letters * (16 - extra)
        return bs

    # delete the added padding to get correct decrypted message
    def delete_padding(message):
        last_char = message[-1]
        if ord(last_char) < 32:
            return message.rstrip(last_char)
        else:
            return message

    # check whether the key/ iv/ plaintext is a bytes-like object and has the correct size
    @staticmethod
    def check_bytes(bs, desc, check):
        if not isinstance(bs, (bytes, bytearray)):
            raise TypeError(f"{desc} must be a bytes-like object")
        if not check(len(bs)):
            bs = AES.add_padding(bs)
        return bytes(bs)

    @staticmethod
    def xor_blocks(bs1, bs2):
        return bytes(b1 ^ b2 for b1, b2 in zip(bs1, bs2))

    @staticmethod
    def text_check(n):
        return n and not n % 16

    # The round constants used in key expansion.
    # rcon[0] is never actually used, while rcon[i] could also
    # be computed during runtime as AES.mul(1 << (i - 1), 1).
    rcon = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

    # The S-box and inverse S-box used in SubBytes() and InvSubBytes().
    s_box = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
        202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
        183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
        4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
        9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
        83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
        208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
        81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
        205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
        96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
        224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
        231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
        186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
        112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
        225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
    ]
    inv_s_box = [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
        124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
        84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
        8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
        114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
        108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
        144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
        208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
        58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
        150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
        71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
        252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
        31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
        96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
        160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
    ]

    # The irreducible polynomial m(x), i.e. x**8 + x**4 + x**3 + x + 1.
    m_x = 0b100011011
