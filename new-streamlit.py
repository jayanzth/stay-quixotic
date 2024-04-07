import random
import streamlit as st
import tensorflow as tf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
import hmac
import hashlib
import time

# Load MNIST dataset
(train_images, train_labels), _ = tf.keras.datasets.mnist.load_data()

# Preprocess the data
train_images = train_images.reshape((len(train_images), -1)) / 255.0  # Flatten and normalize
train_labels = tf.keras.utils.to_categorical(train_labels, num_classes=10)  # Convert labels to one-hot encoding

# Function to generate keys
def generate_keys():
    keys = []
    progress_bar = st.progress(0)
    message = st.empty()
    message.text("Generating keys...")
    for i in range(3):
        time.sleep(1)  # Simulate key generation process
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        keys.append((private_key, public_key))
        progress_bar.progress((i+1)/3)  # Update progress bar
    message.text("Keys generated.")
    return keys


# Function to send keys to the server
def send_keys(users, nodes, server):
    for user in users:
        server.receive_keys([(priv_key, pub_key) for priv_key, pub_key in user[1]])
    for node in nodes:
        server.receive_keys([(priv_key, pub_key) for priv_key, pub_key in node[1]])
    st.write("Keys sent to server.")

# Keys Advertising
class Server:
    def __init__(self):
        self.user_keys = []
        self.node_keys = []

    def receive_keys(self, keys):
        self.user_keys.extend(keys)

    def broadcast_keys(self):
        return self.user_keys, self.node_keys

# Key Sharing
def generate_keys_2():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def establish_shared(users, nodes):
    st.write("Establishing shared secrets...")
    for node_index, node in enumerate(nodes):
        for user_index, user in enumerate(users):
            shared_secrets = []
            for i in range(3):
                user_priv_key, user_pub_key = generate_keys_2()
                node_priv_key, node_pub_key = generate_keys_2()
                shared_secret = derive_secret(node_priv_key, user_pub_key)
                shared_secrets.append(shared_secret)
            node[2].append(shared_secrets)
    st.write("Shared secrets established.")

def derive_secret(priv_key, pub_key):
    shared_key = priv_key.exchange(ec.ECDH(), pub_key)
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'key_agreement',
        backend=default_backend()
    )
    derived_key = kdf.derive(shared_key)
    return derived_key

def encrypt(data, secret, pub_key):
    st.write("Encrypting data...")
    iv = bytes([random.randint(0, 255) for _ in range(16)])  # Pseudorandom initialization vector
    cipher = Cipher(algorithms.AES(secret), modes.CFB8(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    st.write("Data encrypted.")
    return iv + ciphertext

def encrypt_data(users, nodes):
    for user_index, user in enumerate(users):
        for node in nodes:
            for i in range(3):
                data = bytes([random.randint(0, 255) for _ in range(32)])
                ciphertext = encrypt(data, node[2][user_index][i], user[1][i])
                node[3][i].append(ciphertext)

def decrypt_data(users, nodes):
    for user_index, user in enumerate(users):
        for node in nodes:
            for i in range(3):
                user_priv_key, user_pub_key = user[1][i]
                node_priv_key, node_pub_key = node[1][i]
                secret = derive_secret(node_priv_key, user_pub_key)
                ciphertext = node[3][i][user_index]
                data = decrypt(ciphertext, secret)
                user[2][i] = data

# Masking Input
def mask_input(users, nodes):
    for user in users:
        for node in nodes:
            for i in range(3):
                user_priv_key, user_pub_key = user[1][i]
                node_priv_key, node_pub_key = node[1][i]
                secret = user_priv_key.exchange(ec.ECDH(), node_pub_key)
                masking_value = bytes([random.randint(0, 255) for _ in range(32)])
                user[3][i].append(masking_value)
                masked_input = user[4][i] + masking_value
                mac = gen_mac(user[4][i], secret)
                user[5][i].append(mac)
                node[4][i].append(masked_input)

# Unmasking Input
def unmask_input(nodes, online_users):
    for node in nodes:
        unmasking_vectors = []
        for i in range(3):
            unmasking_vector = bytes([random.randint(0, 255) for _ in range(32)])
            unmasking_vectors.append(unmasking_vector)
        node[5] = unmasking_vectors * len(online_users)

def aggregate_values(users, nodes):
    values = []
    for i in range(3):  
        for j, user in enumerate(users):
            if i < len(nodes[0][4]) and len(nodes[0][4][i]) > j and len(nodes[0][5]) > j * 3 + i: 
                value = user[4][i] + nodes[0][4][i][j] - nodes[0][5][j * 3 + i]
                values.append(value)
    return values

# Verification
def verify_values(users, nodes, values, mac):
    for i in range(min(3, len(values))):  
        for user in users:
            calc_mac = gen_mac(values[i], user[1][i].exchange(ec.ECDH(), nodes[0][1][i]))
            if calc_mac != mac[i]:
                return False
    return True

def gen_mac(data, key):
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

# Training
def train(images, labels):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(128, activation='relu', input_shape=(784,)),
        tf.keras.layers.Dense(10, activation='softmax')
    ])

    model.compile(optimizer='adam',
                  loss='categorical_crossentropy',
                  metrics=['accuracy'])

    st.write("Training local model...")
    history = model.fit(images, labels, epochs=5, batch_size=32, verbose=0)

    return history

def main():
    st.title("Federated Learning Client")
    server = Server()
    
    # Generate user data
    users = []
    for _ in range(5):  
        user_keys = generate_keys()
        user_data = [user_keys, [], [], [], [], []]  
        users.append(user_data)
    
    # Generate auxiliary node data
    nodes = []
    for _ in range(3):  
        node_keys = generate_keys()
        node_data = [node_keys, [], [], [], [], []]  
        nodes.append(node_data)
    
    # Send public keys to the server
    send_keys(users, nodes, server)

    if st.button("Start Training"):
        history = train(train_images, train_labels)
        st.success("Training completed successfully!")
        
        values = aggregate_values(users, nodes)  
        mac = None  
        verification_result = verify_values(users, nodes, values, mac)

        if verification_result:
            st.success("Verification Result: MAC values matched.")
        else:
            st.error("Verification Result: MAC values did not match.")

if __name__ == "__main__":
    main()
