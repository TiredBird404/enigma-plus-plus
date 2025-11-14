# For GUI
import tkinter as tk
import time
from tkinter import messagebox
# For Cryption
import hashlib
import zlib
import secrets
import hmac
import base64
from argon2.low_level import hash_secret_raw, Type

BASE64_CHARS : str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_FILL : str = '='

class CryptionMain:
    def __init__(self, text : str, key : str) -> None:
        self.key = StringProcessor(key).clean_space()
        self.text = text
        # 字节长度
        self.random_length : int = 16
        self.mac_length : int = 32

    def encryption(self) -> str:
        # 压缩与认证生成
        compressed_text : str = StringProcessor(self.text).compress() # 压缩明文，输出其base64数据
        mac : str = self.generate_mac(compressed_text) # 通过压缩后的明文与密钥生成mac

        # 将base64文本与填充字符数分离
        fill_num : int = StringProcessor(compressed_text).base64_reserve_num()
        text_no_fill : str = compressed_text
        if fill_num != 0:
            text_no_fill = text_no_fill[0:-fill_num]

        # 文本打乱
        nonce : str = secrets.token_bytes(self.random_length).hex() # 生成随机值，其将作为打乱目前文本的种子值
        unrested_text : str = StringProcessor(text_no_fill + str(fill_num) + mac).unrest(nonce) # 使用随机值打乱文本与mac的结合

        # 密钥处理
        salt : bytes = secrets.token_bytes(self.random_length) # 生成随机盐
        cryption_parameter : str = self.generate_cryption_parameter(salt)

        # 文本加密
        enigma = EnigmaMachine(nonce + unrested_text, cryption_parameter) # 将打乱随机值与打乱后的文本结合并将此与密钥、随机盐一同置入恩尼各玛机
        encrypted_text : str = enigma.encrypte()

        salt_base16 : str = salt.hex() # 将随机盐转为16进制字符串
        processed_text : str = salt_base16 + encrypted_text # 将随机盐与加密文本结合

        # 最终打乱
        hash_key : str = hashlib.sha3_512(self.key.encode('utf-8')).hexdigest()
        unrested_result : str = StringProcessor(processed_text).unrest(hash_key)

        return unrested_result
    
    def decryption(self) -> tuple[bool,str]:
        # 十六进制参数占用位置
        random_hex_lenght : int = self.random_length * 2
        mac_hex_lenght : int = self.mac_length * 2

        # 恢复打乱文本
        encrypted_text : str = StringProcessor(self.text).base64_filter()
        hash_key : str = hashlib.sha3_512(self.key.encode('utf-8')).hexdigest()
        encrypted_rested_result : str = StringProcessor(encrypted_text).rest(hash_key)

        # 恢复加密参数
        salt_base16 : str = encrypted_rested_result[:random_hex_lenght] # 读取十六进制随机盐
        try:
            salt : bytes = bytes.fromhex(salt_base16) # 将十六进制的随机盐转为字节数据
        except:
            return False, ''
        cryption_parameter : str = self.generate_cryption_parameter(salt)

        # 解密
        enigma = EnigmaMachine(encrypted_rested_result[random_hex_lenght:], cryption_parameter) # 将打乱随机值与打乱后的文本结合并将此与密钥、随机盐一同置入恩尼各玛机
        decrypted_text : str = enigma.encrypte()

        # 获取打乱随机值
        nonce_hex : str = decrypted_text[:random_hex_lenght]
        try:
            bytes.fromhex(nonce_hex)
        except:
            return False, ''

        # 获取原压缩文本+mac
        rested_text : str = StringProcessor(decrypted_text[random_hex_lenght:]).rest(nonce_hex)
        filtered_compressed_text : str = rested_text[:-mac_hex_lenght]
        mac : str = rested_text[-mac_hex_lenght:]

        # 还原压缩文本
        try:
            fill_num : int = int(filtered_compressed_text[-1])
        except:
            return False, ''
        fill : str = ''
        for _ in range(fill_num):
            fill += BASE64_FILL
        compressed_text : str = filtered_compressed_text[:-1] + fill

        # 通过当前文本与密钥生成mac，并检查是否与文本包含的相符
        check_mac : str = self.generate_mac(compressed_text)
        if hmac.compare_digest(check_mac, mac):
            return StringProcessor(compressed_text).decompress()
        else:
            return False, ''
    
    def generate_mac(self,text:str) -> str: # 生成mac认证
        hmac_result : bytes = hmac.new(
            key=self.key.encode('utf-8'),
            msg=text.encode('utf-8'),
            digestmod=hashlib.sha3_512
        ).digest()
        hmac_shake : bytes = hashlib.shake_256(hmac_result).digest(self.mac_length) # 使用shake256生成指定长度
        return hmac_shake.hex()

    def generate_cryption_parameter(self,salt : bytes) -> str:
        return  hash_secret_raw( # 通过随机盐与密钥生成参数
            secret=self.key.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=256*1024, # KB
            parallelism=4,
            hash_len=256, # bytes
            type=Type.ID
        ).hex()

class EnigmaMachine:
    def __init__(self, text : str, key : str) -> None: # key应为十六进制数据
        self.text = text
        self.key : str = key

    def encrypte(self) -> str:
        alphabet : str = StringProcessor(BASE64_CHARS).unrest(self.key) # 将恩尼各玛机所依赖的字符表从一开始便被密钥+随机盐的argon2结果打乱
        parameter_processor = ParameterProcessing(self.key, alphabet)
        turn_extent : int = parameter_processor.turn_extent_generation()
        deflect : list[int] = parameter_processor.deflect_generation()
        rotors : list[str] = parameter_processor.rotors_generation(deflect)
        conversion_1 : list[str] = parameter_processor.character_conversion_generator(0)
        conversion_2 : list[str] = parameter_processor.character_conversion_generator(1)

        text : str = self.text
        result : str = ""
        for letter in text:
            letter = self.character_conversion(letter, conversion_1)
            for i, rotor in enumerate(rotors):
                index_alphabet = alphabet.index(letter)
                index_deflected = (index_alphabet + deflect[i]) % len(alphabet)
                letter_index = rotor.index(alphabet[index_deflected]) 
                letter = alphabet[letter_index]
            letter = self.character_conversion(letter, conversion_2)
            for l in reversed(range(len(rotors))):
                index_alphabet = alphabet.index(letter)
                rotor_letter = rotors[l][index_alphabet]
                rotor_letter_index = alphabet.index(rotor_letter)
                index_deflected = (rotor_letter_index - deflect[l]) % len(alphabet)
                letter = alphabet[index_deflected]
            letter = self.character_conversion(letter, conversion_1)
            deflect = self.turn_deflect(deflect, turn_extent)
            result += letter
        return result

    @staticmethod
    def character_conversion(letter : str, parameter : list[str]) -> str:
        for c in parameter:
            if letter in c:
                letter_index = c.index(letter)
                letter = c[(letter_index + 1) % 2]
                break
        return letter
    
    @staticmethod
    def turn_deflect(deflect : list[int], turn_extent : int) -> list[int]:
        length_alphabet : int = len(BASE64_CHARS)
        turned_deflect : list[int] = deflect.copy()
        length_deflect : int = len(deflect)
        turned_deflect[0] += turn_extent
        for i in range(length_deflect - 1):
            num : int = turned_deflect[i]
            carry : int = num // length_alphabet
            turned_deflect[i + 1] += carry
            num %= length_alphabet
        turned_deflect[length_deflect - 1] %= length_alphabet
        return turned_deflect

class ParameterProcessing:
    def __init__(self, key : str, alphabet : str) -> None: # key应为十六进制数据, 且长度应为512字符
        self.parameters : tuple[str,tuple[str,str]]= self.process_key(key)
        self.alphabet : str = alphabet

    def turn_extent_generation(self) -> int:
        parameter_tiny : bytes = hashlib.shake_256(bytes.fromhex(self.parameters[0])).digest(4) # 通过shake256将参数转为指定长度
        original_value : int = int.from_bytes(parameter_tiny, byteorder="big") + 1
        turn_extent : int = self.to_positif_or_negatif(original_value, original_value)
        return turn_extent # 数值坐落于-2^32至2^32

    def deflect_generation(self) -> list[int]:
        rotors_max_num : int = 64
        rotors_min_num : int = 32

        parameter : str = self.parameters[0]
        parameter_tiny : int = int.from_bytes(hashlib.shake_256(bytes.fromhex(parameter)).digest(1), byteorder="big")
        rotors_num : int = ((parameter_tiny - rotors_min_num) % (rotors_max_num - rotors_min_num + 1)) + rotors_min_num
        
        deflect : list[int] = []
        # 为每个初始偏移参数生成sha256值，并转为int，其基于密钥。
        # 256bits大约为1.16*10^77，与64!的1.27*10^89有一定差距，但如此数量的候选基本足够
        # 同时，因为有负数存在，因此字符库的数量为256bits*2
        # 总轮子数坐落于32个至64个不定
        for i in range(rotors_num):
            value : str = parameter + str(i)
            new_deflect : int = int.from_bytes(hashlib.sha256(value.encode('utf-8')).digest(), byteorder="big")
            new_deflect = self.to_positif_or_negatif(new_deflect, i)
            deflect.append(new_deflect)
        return deflect

    def rotors_generation(self, deflect : list[int]) -> list[str]:
        rotors : list[str] = []
        for d in deflect:
            rotors.append(StringProcessor(self.alphabet).unrest(hex(d)))
        return rotors

    def to_positif_or_negatif(self, value : int, index : int) -> int:
        parameter = self.parameters[0]
        original_value : int = value
        char_parameter : str = parameter[index % len(parameter)] # 通过参数第n个16进制值来决定此值为正或负
        decide_value = value + int(char_parameter, 16)
        if decide_value % 2 == 1: # 若此16进制值为奇数，数值则转为负数
            original_value *= -1
        return original_value

    def character_conversion_generator(self, num_conversion : int) -> list[str]:
        parameter : str = self.parameters[1][num_conversion]
        alphabet_unrested : str = StringProcessor(self.alphabet).unrest(parameter) # 将现有的字符库再打乱
        character_conversion : list[str] = [alphabet_unrested[l:l+2] for l in range(0, len(alphabet_unrested), 2)] # 将此打乱的字符库以每两个字符切分至数组中
        return character_conversion

    def process_key(self, key : str) -> tuple[str,tuple[str,str]]:
        division : tuple[str,str] = StringProcessor(key).division() # 将参数一分为二
        conversion_parameters : tuple[str,str] = StringProcessor(division[1]).division() # 将字符转换的参数再一分为二，以获得两个字符转换参数
        return division[0], conversion_parameters

class StringProcessor:
    def __init__(self, string : str)-> None:
        self.string = string

    def division(self) -> tuple[str, str]: # 将字符串一分为二
        length_value : int = len(self.string)
        half_length : int = int(length_value / 2)
        half_1 : str = self.string[:half_length]
        half_2 : str = self.string[half_length:]
        return half_1, half_2

    def clean_space(self) -> str: # 清除字符串的空白文本
        return ''.join(self.string.split())

    def compress(self) -> str: # 压缩字符串，并输出base64文本
        data : bytes = self.string.encode('utf-8')
        data_compressed : bytes = zlib.compress(data)
        compressed_string : bytes = base64.b64encode(data_compressed)
        return compressed_string.decode('utf-8')
    
    def decompress(self) -> tuple[bool, str]: # 解压base64字符串，并输出原文
        try:
            data : bytes = base64.b64decode(self.string)
        except:
            return False, ''
        try:
            decompressed_data : bytes = zlib.decompress(data)
        except:
            return False, ''
        return True, decompressed_data.decode("utf-8")
    
    def unrest(self, seed : str) -> str: # 打乱字符串
        chars = list(self.string)
        random_numbers : list[int] = []
        for i in range(len(self.string)): # 种子通过哈希算法生成一系列伪随机数
            value : str = seed + str(i)
            hash_parameter : bytes = hashlib.sha256(value.encode('utf-8')).digest()
            random_numbers.append(int.from_bytes(hash_parameter,byteorder="big"))
        for f in range(len(self.string) - 1, 0, -1): # 使用伪随机数进行打乱，使用Fisher-Yates算法
            y = random_numbers[f] % (f + 1)
            chars[f], chars[y] = chars[y], chars[f]
        return ''.join(chars)
    
    def rest(self, seed : str) -> str: # 以相同的种子恢复字符串
        string_length : int = len(self.string)
        chars = list(self.string)
        random_numbers : list[int] = []
        for i in range(string_length): # 种子通过哈希算法生成一系列伪随机数
            value : str = seed + str(i)
            hash_parameter : bytes = hashlib.sha256(value.encode('utf-8')).digest()
            random_numbers.append(int.from_bytes(hash_parameter,byteorder="big"))
        for f in range(1, string_length): # 使用伪随机数，进行逆向Fisher-Yates
            y = random_numbers[f] % (f + 1)
            chars[f], chars[y] = chars[y], chars[f]
        return ''.join(chars)

    def base64_reserve_num(self) -> int: # 获取base64字符串的填充字符数量
        reserved_num : int = 0
        for char in reversed(self.string):
            if char != BASE64_FILL:
                break
            reserved_num += 1
        return reserved_num
    
    def base64_filter(self) -> str: # 去除所有不包含在base64内的字符，不包括填充字符
        filtered_string : str = ''
        base_with_fill : str = BASE64_CHARS + BASE64_FILL
        for char in self.string:
            if char not in base_with_fill:
                continue
            filtered_string += char
        return filtered_string

class UIManager:
    def __init__(self, root : tk.Tk) -> None:
        self.root = root
        self.ui_setup()
    
    def ui_setup(self) -> None: # 配置GUI部件
        self.root.title("Enigma++")
        self.root.geometry("800x640")
        self.root.resizable(False,False)
        self.root.option_add("*Font", ("Noto Sans Mono",14))

        self.key_entry = tk.Entry(self.root)
        self.text_box = tk.Text(self.root)
        self.scrollbar = tk.Scrollbar(self.root,command=self.text_box.yview)

        self.encryption_button = tk.Button(
            self.root,
            text="加密",
            command=self.access_encryption
        )
        self.decryption_button = tk.Button(
            self.root,
            text="解密",
            command=self.access_decryption
        )

        self.key_entry.place(x=20,y=15,width=760,height=35)
        self.text_box.place(x=20, y=55, width=745, height=510)
        self.scrollbar.place(x=765, y=55, width=15, height=510)
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.encryption_button.place(x=20, y=575,width=370, height=50)
        self.decryption_button.place(x=410, y=575,width=370, height=50)
        
        self.processing_ui(False)
    
    def processing_ui(self, is_processing : bool) -> None: # 配置处理时的程序状态
        if is_processing == True:
            self.root.config(cursor="watch")
            self.text_box.config(cursor="watch",state = "disabled")
            self.key_entry.config(cursor="watch",state = "disabled")
            self.encryption_button.config(state = "disabled")
            self.decryption_button.config(state = "disabled")
        else:
            self.root.config(cursor="arrow")
            self.text_box.config(cursor="xterm",state = "normal")
            self.key_entry.config(cursor="xterm",state = "normal")
            self.encryption_button.config(state = "normal")
            self.decryption_button.config(state = "normal")
        self.root.update()

    def access_encryption(self) -> None:
        start_time = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        user_text : str = self.text_box.get("1.0", "end-1c")

        cryption_program = CryptionMain(user_text, user_key)
        cryption_result : str = cryption_program.encryption()
        self.processing_ui(False)

        self.set_text_box(cryption_result)
        end_time : float = time.time()
        messagebox.showinfo("加密完成",f"总共花费{str(end_time - start_time)[:5]}秒")
        
    def access_decryption(self) -> None:
        start_time = time.time()
        self.processing_ui(True)
        user_key : str = self.key_entry.get()
        crypted_text : str = self.text_box.get("1.0", "end-1c")

        cryption_program = CryptionMain(crypted_text, user_key)
        cryption_result : tuple[bool,str] = cryption_program.decryption()
        self.processing_ui(False)

        if cryption_result[0] == True:
            self.set_text_box(cryption_result[1])
            end_time : float = time.time()
            messagebox.showinfo("解密完成",f"总共花费{str(end_time - start_time)[:5]}秒")
        else:
            messagebox.showerror("解密失败","密钥、密文不正确。亦或密文被篡改。")

    def set_text_box(self, new_text : str) -> None:
        self.text_box.delete("1.0", "end-1c")
        self.text_box.insert("1.0", new_text)

def main() -> None:
    root = tk.Tk()
    app = UIManager(root)
    _ = app
    root.mainloop()

if __name__ == "__main__":
    main()
