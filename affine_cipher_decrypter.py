import re
from typing import Set, Tuple, List


class AffineCipherDecrypter:
    """
    Class for decrypting text encrypted using the Affine cipher.
    """

    def __init__(self, ciphertext: str, word_bank_file: str, alphabet_size: int):
        """
        Initialize the AffineCipherDecrypter.

        :param ciphertext: The encrypted text to decrypt.
        :param word_bank_file: The file path to a word bank used for scoring decrypted text.
        :param alphabet_size: The size of the alphabet (e.g., 26 for English).
        """
        self.ciphertext = ciphertext
        self.word_bank = AffineCipherDecrypter.load_word_bank(word_bank_file)
        self.alphabet_size = alphabet_size

    @staticmethod
    def load_word_bank(word_bank_file: str) -> Set[str]:
        """
        Load a word bank from a file.

        :param word_bank_file: The file path to the word bank.
        :return: A set of words from the word bank.
        """
        word_set = set()

        with open(word_bank_file, 'r') as file:
            for line in file:
                word = line.strip().lower()
                word_set.add(word)

        return word_set

    def find_possible_plaintext(self) -> List[str]:
        """
        Find the best possible plaintext text by using brute force to find the best combination of shift and multiplier.

        :return: A list of possible plaintext (decrypted)
        """
        possible_plaintext = {}

        for shift in range(self.alphabet_size):
            for multiplier in range(1, self.alphabet_size):
                # Checks whether the multiplier is valid, i.e. it is coprime with the alphabet size
                inverse = self.modular_inverse(multiplier, self.alphabet_size)
                if inverse is None:
                    continue

                plaintext = self.decrypt(self.ciphertext, shift, multiplier)
                score = self.calculate_score(plaintext)

                possible_plaintext[plaintext] = score

        # Get the maximum score of decrypted possible plaintext
        max_score = max(possible_plaintext.values())

        # This handles if there are multiple possible plaintext with the same score
        best_plaintext = []
        for key, value in possible_plaintext.items():
            if value == max_score:
                best_plaintext.append(key)

        return best_plaintext

    def decrypt(self, ciphertext: str, shift: int, multiplier: int) -> str:
        """
        Decrypt the cipher text using the Affine cipher.

        :param ciphertext: The encrypted text to decrypt.
        :param shift: The shift value (number of positions to shift characters).
        :param multiplier: The multiplier value for the affine transformation.
        :return: The decrypted plain text.
        """
        plaintext = ""

        for char in ciphertext:
            if char.isalpha():
                decrypted_char = chr(
                    ((ord(char.lower()) - ord('a') - shift) * self.modular_inverse(multiplier, self.alphabet_size))
                    % self.alphabet_size + ord('a')
                )
                plaintext += decrypted_char.upper() if char.isupper() else decrypted_char
            else:
                plaintext += char

        return plaintext

    @staticmethod
    def modular_inverse(a: int, m: int) -> int | None:
        """
        Compute the modular inverse of a number.

        :param a: The number for which to compute the modular inverse.
        :param m: The modulus.
        :return: The modular inverse if it exists, None otherwise.
        """
        if AffineCipherDecrypter.extended_gcd(a, m)[0] != 1:
            return None

        _, x, _ = AffineCipherDecrypter.extended_gcd(a, m)

        return x % m

    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """
        Extended Euclidean algorithm for computing the greatest common divisor (gcd) and coefficients
        x and y satisfying ax + by = gcd(a, b).

        :param a: The first number.
        :param b: The second number.
        :return: A tuple containing the gcd and the coefficients x and y.
        """
        if a == 0:
            return b, 0, 1

        gcd, x1, y1 = AffineCipherDecrypter.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1

        return gcd, x, y

    def calculate_score(self, plaintext: str) -> int:
        """
        Calculate the score of a decrypted text based on the number of valid words it contains.

        :param plaintext: The decrypted text.
        :return: The score (number of valid words).
        """
        word_pattern = r'\b[a-z]+\b'  # Regular expression pattern to match words
        words = re.findall(word_pattern, plaintext.lower())
        valid_word_count = sum(word in self.word_bank for word in words)
        return valid_word_count

    def run(self):
        """
        Run the decryption process and print the decrypted text.
        """
        possible_plaintext = self.find_possible_plaintext()
        possible_plaintext_length = len(possible_plaintext)

        if possible_plaintext_length > 1:
            print("There are several possible plaintext.")
            for i in range(possible_plaintext_length):
                print(f"Possible plaintext {i}:")
                p = possible_plaintext[i]
                p.strip()
                print(p)
            return

        print(f"Possible plaintext:")
        p = possible_plaintext[0]
        p.strip()
        print(p)


if __name__ == "__main__":
    # Example ciphertext
    ciphertext = """
    FQQHI LZWZX YZFYD ELQOO HQQDI LMPWL MIOZW
    WFZXQ DQGWL FQDIL MBQYD ILMFW KJZIL MFDQY
    AILMF DQYAO LWAWD ZYPQV QDFYD QFZWF DQYAJ
    QBWDQ JKZZX QOIPQ LUQGY OKLJD WEQLY LFZXQ
    OZIPP LQOOM YVQLW ZWEQL YLFZX QWLPC GWDFZ
    XQDQO HWEQL GYOZX QGXIO HQDQF GWDFP QLWDQ
    ZXIOI GXIOH QDQFY LFYLQ UXWAK DAKDQ FJYUE
    ZXQGW DFPQL WDQAQ DQPCZ XIOYL FLWZX ILMAW
    DQJYU EILZW ZXQUX YAJQD ZKDLI LMYPP ACOWK
    PGIZX ILAQJ KDLIL MOWWL YMYIL IXQYD FYZYH
    HILMO WAQGX YZPWK FQDZX YLJQB WDQOK DQPCO
    YIFIO KDQPC ZXYZI OOWAQ ZXILM YZACG ILFWG
    PYZZI UQPQZ AQOQQ ZXQLG XYZZX QDQYZ IOYLF
    ZXIOA COZQD CQRHP WDQPQ ZACXQ YDZJQ OZIPP
    YAWAQ LZYLF ZXIOA COZQD CQRHP WDQZI OZXQG
    ILFYL FLWZX ILMAW DQWHQ LXQDQ IBPKL MZXQO
    XKZZQ DGXQL GIZXA YLCYB PIDZY LFBPK ZZQDI
    LZXQD QOZQH HQFYO ZYZQP CDYVQ LWBZX QOYIL
    ZPCFY COWBC WDQLW ZZXQP QYOZW JQIOY LUQAY
    FQXQL WZYAI LKZQO ZWHHQ FWDOZ YCQFX QJKZG
    IZXAI QLWBP WDFWD PYFCH QDUXQ FYJWV QACUX
    YAJQD FWWDH QDUXQ FKHWL YJKOZ WBHYP PYOTK
    OZYJW VQACU XYAJQ DFWWD HQDUX QFYLF OYZYL
    FLWZX ILMAW DQZXQ LZXIO QJWLC JIDFJ QMKIP
    ILMAC OYFBY LUCIL ZWOAI PILMJ CZXQM DYVQY
    LFOZQ DLFQU WDKAW BZXQU WKLZQ LYLUQ IZGWD
    QZXWK MXZXC UDQOZ JQOXW DLYLF OXYVQ LZXWK
    IOYIF YDZOK DQLWU DYVQL MXYOZ PCMDI AYLFY
    LUIQL ZDYVQ LGYLF QDILM BDWAZ XQLIM XZPCO
    XWDQZ QPPAQ GXYZZ XCPWD FPCLY AQIOW LZXQL
    IMXZO HPKZW LIYLO XWDQS KWZXZ XQDYV QLLQV
    QDAWD QAKUX IAYDV QPPQF ZXIOK LMYIL PCBWG
    PZWXQ YDFIO UWKDO QOWHP YILPC ZXWKM XIZOY
    LOGQD PIZZP QAQYL ILMPI ZZPQD QPQVY LUCJW
    DQBWD GQUYL LWZXQ PHYMD QQILM ZXYZL WPIVI
    LMXKA YLJQI LMQVQ DCQZG YOJPQ OOQFG IZXOQ
    QILMJ IDFYJ WVQXI OUXYA JQDFW WDJID FWDJQ
    YOZKH WLZXQ OUKPH ZKDQF JKOZY JWVQX IOUXY
    AJQDF WWDGI ZXOKU XLYAQ YOLQV QDAWD Q
    """

    word_bank_file = "word_bank/english.txt"

    decrypter = AffineCipherDecrypter(ciphertext, word_bank_file, 26)
    decrypter.run()
