import time
# S-box转换表
s_box1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 0, 2]]
s_box2 = [[0, 1, 2, 3], [2, 3, 1, 0], [3, 0, 1, 2], [2, 1, 0, 3]]

# IP置换表
ip_table = [2, 6, 3, 1, 4, 8, 5, 7]

# IP逆置换表
ip_inv_table = [4, 1, 3, 5, 7, 2, 8, 6]

# 轮函数EP置换表
ep_table = [4, 1, 2, 3, 2, 3, 4, 1]

# SP置换表
sp_table = [2, 4, 3, 1]

class SDES:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        # 将明文转换为二进制字符串
        binary_plaintext = bin(int(plaintext, 2))[2:].zfill(8)

        # 初始置换
        ip_result = self.permutation(binary_plaintext, ip_table)

        # 生成子密钥
        key1, key2 = self.generate_subkeys()

        # 切分明文为左右两部分
        left, right = ip_result[:4], ip_result[4:]

        # 8轮迭代加密
        for i in range(8):
            new_left = right
            new_right = self.xor(left, self.f_function(right, key1 if i % 2 == 0 else key2))
            left, right = new_left, new_right

        # 最终逆置换
        ciphertext = self.permutation(right + left, ip_inv_table)

        return ciphertext

    def decrypt(self, ciphertext):
        # 将密文转换为二进制字符串
        binary_ciphertext = bin(int(ciphertext, 2))[2:].zfill(8)

        # 初始置换
        ip_result = self.permutation(binary_ciphertext, ip_table)

        # 生成子密钥
        key1, key2 = self.generate_subkeys()

        # 切分密文为左右两部分
        left, right = ip_result[:4], ip_result[4:]

        # 8轮迭代解密
        for i in range(8):
            new_left = right
            new_right = self.xor(left, self.f_function(right, key2 if i % 2 == 0 else key1))
            left, right = new_left, new_right

        # 最终逆置换
        plaintext = self.permutation(right + left, ip_inv_table)

        return plaintext

    def generate_subkeys(self):
        # 初始密钥置换
        p10_result = self.permutation(self.key, [3, 5, 2, 7, 4, 10, 1, 9, 8, 6])

        # 循环左移
        left_shift_1 = self.left_shift(p10_result[:5], 1)
        left_shift_2 = self.left_shift(p10_result[5:], 2)

        # 选择置换P8
        key1 = self.permutation(left_shift_1 + left_shift_2, [6, 3, 7, 4, 8, 5, 10, 9])

        # 再次左移
        left_shift_1 = self.left_shift(left_shift_1, 1)
        left_shift_2 = self.left_shift(left_shift_2, 2)

        # 选择置换P8
        key2 = self.permutation(left_shift_1 + left_shift_2, [6, 3, 7, 4, 8, 5, 10, 9])

        return key1, key2

    @staticmethod
    def permutation(input_str, table):
        return ''.join(input_str[i - 1] for i in table)

    @staticmethod
    def xor(binary_str1, binary_str2):
        return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(binary_str1, binary_str2))

    @staticmethod
    def left_shift(input_str, num_bits):
        return input_str[num_bits:] + input_str[:num_bits]

    def f_function(self, input_str, key):
        # 进行EP扩展置换
        ep_result = self.permutation(input_str, ep_table)

        # 与子密钥进行异或运算
        xor_result = self.xor(ep_result, key)

        # S1，S2盒置换
        s1_row = int(xor_result[:2], 2)
        s1_col = int(xor_result[2:4], 2)
        s2_row = int(xor_result[4:6], 2)
        s2_col = int(xor_result[6:], 2)

        s1_output = bin(s_box1[s1_row][s1_col])[2:].zfill(2)
        s2_output = bin(s_box2[s2_row][s2_col])[2:].zfill(2)

        # 进行SP置换
        sp_result = self.permutation(s1_output + s2_output, sp_table)

        return sp_result
def brute_force_attack(plaintext, ciphertext):
    for key in range(1024):
        binary_key = bin(key)[2:].zfill(10)
        sdes = SDES(binary_key)
        encrypted_text = sdes.encrypt(plaintext)
        if encrypted_text == ciphertext:
            return binary_key
    return None

def test_elapsed_time(key, plaintext):
    sdes = SDES(key)
    start_time = time.perf_counter()
    ciphertext = sdes.encrypt(plaintext)
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return ciphertext, elapsed_time

# 给定的明文和密文
plaintext = "10101010"
ciphertext = "11111110"

# 枚举法找出密钥
key_found = brute_force_attack(plaintext, ciphertext)
if key_found:
    print("找到了匹配的密钥:", key_found)
else:
    print("未找到匹配的密钥")

# 测试加密时间
key = "0000000000"  # 假设找到匹配的密钥
ciphertext, elapsed_time = test_elapsed_time(key, plaintext)
print("加密时间:", elapsed_time)