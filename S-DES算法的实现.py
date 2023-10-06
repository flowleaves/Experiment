from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QLineEdit

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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("S-DES加解密")

        self.label_key = QLabel("密钥（10位二进制）", self)
        self.label_key.setGeometry(50, 50, 200, 25)
        self.edit_key = QLineEdit(self)
        self.edit_key.setGeometry(50, 75, 200, 25)

        self.label_plain = QLabel("明文/密文（8位二进制）", self)
        self.label_plain.setGeometry(50, 125, 200, 25)
        self.edit_plain = QLineEdit(self)
        self.edit_plain.setGeometry(50, 150, 200, 25)

        self.button_encrypt = QPushButton("加密", self)
        self.button_encrypt.setGeometry(50, 200, 75, 25)
        self.button_encrypt.clicked.connect(self.encrypt)

        self.button_decrypt = QPushButton("解密", self)
        self.button_decrypt.setGeometry(175, 200, 75, 25)
        self.button_decrypt.clicked.connect(self.decrypt)

        self.label_result = QLabel(self)
        self.label_result.setGeometry(50, 250, 200, 25)

    def encrypt(self):
        key = self.edit_key.text().strip()
        plaintext = self.edit_plain.text().strip()

        if len(key) != 10 or len(plaintext) != 8 or not all(bit in ('0', '1') for bit in key+plaintext):
            self.label_result.setText("请输入正确的密钥和明文（8位二进制数）")
            return

        sdes = SDES(key)
        ciphertext = sdes.encrypt(plaintext)

        self.label_result.setText(f"密文：{ciphertext}")

    def decrypt(self):
        key = self.edit_key.text().strip()
        ciphertext = self.edit_plain.text().strip()

        if len(key) != 10 or len(ciphertext) != 8 or not all(bit in ('0', '1') for bit in key+ciphertext):
            self.label_result.setText("请输入正确的密钥和密文（8位二进制数）")
            return

        sdes = SDES(key)
        plaintext = sdes.decrypt(ciphertext)

        self.label_result.setText(f"明文：{plaintext}")


if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec()