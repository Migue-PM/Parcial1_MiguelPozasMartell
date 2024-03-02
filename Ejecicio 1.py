from Crypto.Util.number import getPrime, inverse
import hashlib

# Longitud claves
key_length = 1024

# Función para hashing  
def hash_text(text):
    hash_func = hashlib.sha256()
    hash_func.update(text.encode('utf-8'))  
    return hash_func.hexdigest()

# Mensaje
message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam at cursus arcu. Phasellus porttitor est ac nibh egestas, sed tempus lorem pretium. In gravida, ante sed venenatis dapibus, nisi orci auctor diam, id maximus justo nibh vel urna. Nulla elementum iaculis dui, blandit imperdiet dui pulvinar et. Sed vitae vulputate ante. Aliquam eu diam quis mauris varius sollicitudin. Pellentesque in lectus risus. Nulla elementum aliquet ex vel consectetur. Quisque ante libero, imperdiet non volutpat nec, auctor non orci. Nam laoreet ipsum eu leo ultrices commodo.Ut interdum condimentum lorem, id dictum sapien ultrices eu. Cras ac dui fermentum ligula rutrum mollis. Nunc lacinia mi finibus orci aliquam aliquam aliquet ut libero. Donec mauris orci, accumsan id ultrices eu, sodales at ante. Aliquam laoreet finibus nisi sit amet pretium. Vestibulum vehicula lacus vitae aliquam eleifend. Nam sit amet fringilla velit. Nam at malesuada metus, a faucibus mauris. Class aptent taciti sociosqu." * 10 

# Hash mensaje original  
original_hash = hash_text(message)  

# Dividimos en bloques  
message_parts = [message[i:i+128] for i in range(0, len(message), 128)]

# Claves Alice
p_alice = getPrime(key_length)
q_alice = getPrime(key_length)  
n_alice = p_alice * q_alice
phi_alice = (p_alice - 1) * (q_alice - 1)  
e_alice = 65537
d_alice = inverse(e_alice, phi_alice)  

# Claves Bob
p_bob = getPrime(key_length)  
q_bob = getPrime(key_length)
n_bob = p_bob * q_bob  
phi_bob = (p_bob - 1) * (q_bob - 1)  
e_bob = 65537
d_bob = inverse(e_bob, phi_bob)

# Ciframos  
cipher_parts = []  
for part in message_parts:
    bytes = part.encode()  
    num = int.from_bytes(bytes, "big")
    cipher_parts.append(pow(num, e_bob, n_bob))

# Desciframos
decrypted_parts = []  
for part in cipher_parts:
    num = pow(part, d_bob, n_bob) 
    bytes = num.to_bytes((num.bit_length() + 7) // 8, "big")
    decrypted_parts.append(bytes.decode())  

# Reconstruimos  
decrypted_msg = "".join(decrypted_parts) 
print("Mensaje descifrado:", decrypted_msg) 
print("Mensaje original:", message)

# Generamos el hash del mensaje descifrado
decrypted_hash = hash_text(decrypted_msg)  

# Comparamos hashes
print("Los hashes coinciden:", decrypted_hash == original_hash)
