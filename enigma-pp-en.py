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
        # Bytes length
        self.random_length : int = 16
        self.mac_length : int = 32

    def encryption(self) -> str:
        # Compression and MAC generation
        compressed_text : str = StringProcessor(self.text).compress() # Compress plaintext and output its Base64 data
        mac : str = self.generate_mac(compressed_text) # Generate a MAC using the compressed plaintext and the key

        # Separate the base64 text from the padding characters
        fill_num : int = StringProcessor(compressed_text).base64_reserve_num()
        text_no_fill : str = compressed_text
        if fill_num != 0:
            text_no_fill = text_no_fill[0:-fill_num]

        # Text scrambling
        nonce : str = secrets.token_bytes(self.random_length).hex() # Generate a random value, which will serve as the seed value for scrambling the text.
        unrested_text : str = StringProcessor(text_no_fill + str(fill_num) + mac).unrest(nonce) # Shuffle text using random values

        # Key handling
        salt : bytes = secrets.token_bytes(self.random_length) # Generate random salt
        cryption_parameter : str = self.generate_cryption_parameter(salt)

        # Text encryption
        # Combine the scrambled random values with the scrambled text, 
        # Then feed this along with the key and random salt into the Enigma machine.
        enigma = EnigmaMachine(nonce + unrested_text, cryption_parameter)
        encrypted_text : str = enigma.encrypte()

        salt_base16 : str = salt.hex() # Convert random salt to a hexadecimal string
        processed_text : str = salt_base16 + encrypted_text # Combine random salt with ciphertext

        # Final scrambling
        hash_key : str = hashlib.sha3_512(self.key.encode('utf-8')).hexdigest()
        unrested_result : str = StringProcessor(processed_text).unrest(hash_key)

        return unrested_result
    
    def decryption(self) -> tuple[bool,str]:
        # Hexadecimal parameter location
        random_hex_lenght : int = self.random_length * 2
        mac_hex_lenght : int = self.mac_length * 2

        # Restore scrambled text
        encrypted_text : str = StringProcessor(self.text).base64_filter()
        hash_key : str = hashlib.sha3_512(self.key.encode('utf-8')).hexdigest()
        encrypted_rested_result : str = StringProcessor(encrypted_text).rest(hash_key)

        # Restore encryption parameters
        salt_base16 : str = encrypted_rested_result[:random_hex_lenght] # 读取十六进制随机盐
        try:
            salt : bytes = bytes.fromhex(salt_base16) # Convert the hexadecimal random salt to byte data
        except:
            return False, ''
        cryption_parameter : str = self.generate_cryption_parameter(salt)

        # Decryption
        enigma = EnigmaMachine(encrypted_rested_result[random_hex_lenght:], cryption_parameter)
        decrypted_text : str = enigma.encrypte()

        # Get the shuffled random value
        nonce_hex : str = decrypted_text[:random_hex_lenght]
        try:
            bytes.fromhex(nonce_hex)
        except:
            return False, ''

        # Retrieve the original compressed text + mac
        rested_text : str = StringProcessor(decrypted_text[random_hex_lenght:]).rest(nonce_hex)
        filtered_compressed_text : str = rested_text[:-mac_hex_lenght]
        mac : str = rested_text[-mac_hex_lenght:]

        # Restore compressed text
        try:
            fill_num : int = int(filtered_compressed_text[-1])
        except:
            return False, ''
        fill : str = ''
        for _ in range(fill_num):
            fill += BASE64_FILL
        compressed_text : str = filtered_compressed_text[:-1] + fill

        # Generate a MAC using the current text and key, 
        # And verify whether it matches the one contained within the text.
        check_mac : str = self.generate_mac(compressed_text)
        if hmac.compare_digest(check_mac, mac):
            return StringProcessor(compressed_text).decompress()
        else:
            return False, ''
    
    def generate_mac(self,text:str) -> str: # Generate MAC
        hmac_result : bytes = hmac.new(
            key=self.key.encode('utf-8'),
            msg=text.encode('utf-8'),
            digestmod=hashlib.sha3_512
        ).digest()
        hmac_shake : bytes = hashlib.shake_256(hmac_result).digest(self.mac_length) # Generate a specified length using shake256
        return hmac_shake.hex()

    def generate_cryption_parameter(self,salt : bytes) -> str:
        return  hash_secret_raw( # Generating parameters through random salt and key
            secret=self.key.encode('utf-8'),
            salt=salt,
            time_cost=4,
            memory_cost=256*1024, # KB
            parallelism=4,
            hash_len=256, # bytes
            type=Type.ID
        ).hex()

class EnigmaMachine:
    def __init__(self, text : str, key : str) -> None: # The key should be hexadecimal data.
        self.text = text
        self.key : str = key

    def encrypte(self) -> str:
        # The character table that the Enigma machine relies upon is scrambled from the outset by the argon2 result of the key plus random salt.
        alphabet : str = StringProcessor(BASE64_CHARS).unrest(self.key) 
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
    def __init__(self, key : str, alphabet : str) -> None: # The key should be hexadecimal data, and its length should be 512 characters.
        self.parameters : tuple[str,tuple[str,str]]= self.process_key(key)
        self.alphabet : str = alphabet

    def turn_extent_generation(self) -> int:
        parameter_tiny : bytes = hashlib.shake_256(bytes.fromhex(self.parameters[0])).digest(4) # Convert parameters to a specified length using shake256
        original_value : int = int.from_bytes(parameter_tiny, byteorder="big") + 1
        turn_extent : int = self.to_positif_or_negatif(original_value, original_value)
        return turn_extent # The value lies between -2^32 and 2^32.

    def deflect_generation(self) -> list[int]:
        rotors_max_num : int = 64
        rotors_min_num : int = 32

        parameter : str = self.parameters[0]
        parameter_tiny : int = int.from_bytes(hashlib.shake_256(bytes.fromhex(parameter)).digest(1), byteorder="big")
        rotors_num : int = ((parameter_tiny - rotors_min_num) % (rotors_max_num - rotors_min_num + 1)) + rotors_min_num
        
        deflect : list[int] = []
        # Generate a SHA-3-256 value for each initial offset parameter, converting it to an integer based on the key.
        # 256 bits equates to approximately 1.16*10^77, which falls short of 64!'s 1.27*10^89. Nevertheless, this quantity of candidates remains fundamentally sufficient.
        # Concurrently, owing to the presence of negative values, the character set size amounts to 256 bits * 2.
        # The total number of rounds fluctuates between 32 and 64.
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
        char_parameter : str = parameter[index % len(parameter)] # The sign of this value is determined by the nth hexadecimal digit of the parameter.
        decide_value = value + int(char_parameter, 16)
        if decide_value % 2 == 1: # If this hexadecimal value is odd, the number is converted to negative.
            original_value *= -1
        return original_value

    def character_conversion_generator(self, num_conversion : int) -> list[str]:
        parameter : str = self.parameters[1][num_conversion]
        alphabet_unrested : str = StringProcessor(self.alphabet).unrest(parameter) # Shuffle the existing character set
        character_conversion : list[str] = [alphabet_unrested[l:l+2] for l in range(0, len(alphabet_unrested), 2)] # 将此打乱的字符库以每两个字符切分至数组中
        return character_conversion

    def process_key(self, key : str) -> tuple[str,tuple[str,str]]:
        division : tuple[str,str] = StringProcessor(key).division() # Split the parameter into two parts
        conversion_parameters : tuple[str,str] = StringProcessor(division[1]).division() # Split the character conversion parameter into two parts to obtain two character conversion parameters.
        return division[0], conversion_parameters

class StringProcessor:
    def __init__(self, string : str)-> None:
        self.string = string

    def division(self) -> tuple[str, str]: # Split the string into two parts
        length_value : int = len(self.string)
        half_length : int = int(length_value / 2)
        half_1 : str = self.string[:half_length]
        half_2 : str = self.string[half_length:]
        return half_1, half_2

    def clean_space(self) -> str: # Remove whitespace from the string
        return ''.join(self.string.split())

    def compress(self) -> str: # Compress the string and output the Base64 text.
        data : bytes = self.string.encode('utf-8')
        data_compressed : bytes = zlib.compress(data)
        compressed_string : bytes = base64.b64encode(data_compressed)
        return compressed_string.decode('utf-8')
    
    def decompress(self) -> tuple[bool, str]: # Decompress the Base64 string and output the original text.
        try:
            data : bytes = base64.b64decode(self.string)
        except:
            return False, ''
        try:
            decompressed_data : bytes = zlib.decompress(data)
        except:
            return False, ''
        return True, decompressed_data.decode("utf-8")
    
    def unrest(self, seed : str) -> str: # Shuffle the characters
        chars = list(self.string)
        random_numbers : list[int] = []
        for i in range(len(self.string)): # The seed generates a series of pseudorandom numbers via the hash algorithm.
            value : str = seed + str(i)
            hash_parameter : bytes = hashlib.sha256(value.encode('utf-8')).digest()
            random_numbers.append(int.from_bytes(hash_parameter,byteorder="big"))
        for f in range(len(self.string) - 1, 0, -1): # Shuffle using pseudo-random numbers, employing the Fisher-Yates algorithm
            y = random_numbers[f] % (f + 1)
            chars[f], chars[y] = chars[y], chars[f]
        return ''.join(chars)
    
    def rest(self, seed : str) -> str: # Restore the string using the same seed
        string_length : int = len(self.string)
        chars = list(self.string)
        random_numbers : list[int] = []
        for i in range(string_length): # The seed generates a series of pseudorandom numbers via the hash algorithm.
            value : str = seed + str(i)
            hash_parameter : bytes = hashlib.sha256(value.encode('utf-8')).digest()
            random_numbers.append(int.from_bytes(hash_parameter,byteorder="big"))
        for f in range(1, string_length): # Employing pseudo-random numbers to perform reverse Fisher-Yates shuffling
            y = random_numbers[f] % (f + 1)
            chars[f], chars[y] = chars[y], chars[f]
        return ''.join(chars)

    def base64_reserve_num(self) -> int: # The number of padding characters in a base64 string
        reserved_num : int = 0
        for char in reversed(self.string):
            if char != BASE64_FILL:
                break
            reserved_num += 1
        return reserved_num
    
    def base64_filter(self) -> str: # Remove all characters not included within the base64 encoding, except for padding characters.
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
    
    def ui_setup(self) -> None: # Configure GUI components
        self.root.title("Enigma++")
        self.root.geometry("800x640")
        self.root.resizable(False,False)
        self.root.option_add("*Font", ("Noto Sans Mono",14))

        self.key_entry = tk.Entry(self.root)
        self.text_box = tk.Text(self.root)
        self.scrollbar = tk.Scrollbar(self.root,command=self.text_box.yview)

        self.encryption_button = tk.Button(
            self.root,
            text="Encryption",
            command=self.access_encryption
        )
        self.decryption_button = tk.Button(
            self.root,
            text="Decryption",
            command=self.access_decryption
        )

        self.key_entry.place(x=20,y=15,width=760,height=35)
        self.text_box.place(x=20, y=55, width=745, height=510)
        self.scrollbar.place(x=765, y=55, width=15, height=510)
        self.text_box.config(yscrollcommand=self.scrollbar.set)

        self.encryption_button.place(x=20, y=575,width=370, height=50)
        self.decryption_button.place(x=410, y=575,width=370, height=50)
        
        self.processing_ui(False)
    
    def processing_ui(self, is_processing : bool) -> None: # Programme state during configuration processing
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
        messagebox.showinfo("Encryption Done",f"Used {str(end_time - start_time)[:5]}s")
        
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
            messagebox.showinfo("Decryption Done",f"Used {str(end_time - start_time)[:5]}s")
        else:
            messagebox.showerror("Decryption Failed","The key or ciphertext is incorrect.")

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
