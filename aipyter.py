import asyncio
import base58
import hashlib
import random
import ecdsa
import numpy as np
from tensorflow.keras import Model
from tensorflow.keras.layers import Input, Dense, Activation
from tensorflow.keras.optimizers import Adam

def private_key_to_WIF(private_key):
    private_key = bytes.fromhex(private_key)
    extended_key = b"\x80" + private_key
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    return base58.b58encode(extended_key + checksum).decode("utf-8")

def private_key_to_address(private_key, compressed=True):
    private_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1).verifying_key
    if compressed:
        public_key = private_key.to_string(encoding='compressed')
    else:
        public_key = b"\x04" + private_key.to_string()
    sha256_bpk = hashlib.sha256(public_key)
    ripemd160_bpk = hashlib.new("ripemd160", sha256_bpk.digest()).digest()
    network_byte = b"\x00"
    extended_ripemd160 = network_byte + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160).digest()).digest()[:4]
    binary_address = extended_ripemd160 + checksum
    return base58.b58encode(binary_address).decode("utf-8")

def generate_samples(n_samples):
    samples = []
    for i in range(n_samples):
        private_key_int = random.randint(0x30000000000000000, 0x3ffffffffffffffff)
        private_key = hex(private_key_int)[2:].zfill(64)
        public_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1).verifying_key.to_string().hex()
        address = private_key_to_address(private_key)
        samples.append([public_key, address])
    return samples

def build_model(input_shape):
    inputs = Input(shape=input_shape)
    x = Dense(32, activation='relu')(inputs)
    x = Dense(64, activation='relu')(x)
    x = Dense(128, activation='relu')(x)
    x = Dense(256, activation='relu')(x)
    x = Dense(512, activation='relu')(x)
    x = Dense(1024, activation='relu')(x)
    x = Dense(2048, activation='relu')(x)
    x = Dense(4096, activation='relu')(x)
    x = Dense(2048, activation='relu')(x)
    x = Dense(1024, activation='relu')(x)
    x = Dense(512, activation='relu')(x)
    x = Dense(256, activation='relu')(x)
    x = Dense(128, activation='relu')(x)
    x = Dense(64, activation='relu')(x)
    x = Dense(32, activation='relu')(x)
    x = Dense(16, activation='relu')(x)
    x = Dense(8, activation='relu')(x)
    outputs = Dense(1, activation='sigmoid')(x)
    model = Model(inputs=inputs, outputs=outputs)
    model.compile(loss='binary_crossentropy', optimizer=Adam(lr=0.0001))
    return model

async def find_private_key(target_address, model):
    counter = 0
    while True:
        print(f"Generating private key {counter}")
        private_key_int = random.randint(0x30000000000000000, 0x3ffffffffffffffff)
        private_key = hex(private_key_int)[2:].zfill(64)
        
        try:
            address = private_key_to_address(private_key)
            if address == target_address:
                wif = private_key_to_WIF(private_key)
                print(f"Private Key (HEX): {private_key}")
                print(f"Private Key (WIF): {wif}")
                print(f"Bitcoin Address (Compressed): {address}\n")
                return counter
            else:
                # generate point from private key
                sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
                vk = sk.verifying_key
                point = vk.pubkey.point

                # normalize point coordinates
                x = point.x() * pow(2, -point.z())
                y = point.y() * pow(2, -point.z())

                # predict whether the point may correspond to the private key
                prediction = model.predict(np.array([[x, y]]))[0][0]
                if prediction > 0.99:
                    print(f"Found a potential match! Prediction score: {prediction}")
                    wif = private_key_to_WIF(private_key)
                    print(f"Private Key (HEX): {private_key}")
                    print(f"Private Key (WIF): {wif}")
                    print(f"Bitcoin Address (Compressed): {address}\n")
                    return counter

        except Exception:
            pass

        counter += 1
        if counter % 1000 == 0:
            print(f"\rCurrent number of private keys generated: {counter}", end="\n")
            
        print(f"Finished generating private key {counter}")
