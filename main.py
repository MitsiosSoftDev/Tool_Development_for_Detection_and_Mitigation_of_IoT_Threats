import random
import threading
import time
import socket
import ntplib
from sklearn.ensemble import IsolationForest
from sklearn.ensemble import RandomForestRegressor
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


class Server:
    def __init__(self, freq_range):
        self.freq_range = freq_range
        self.original_freq_range = freq_range
        self.safe_freq_range = (5000, 8000)
        self.switch_back_timer = None
        self.connected = False
        self.current_frequency = None
        self.lock = threading.Lock()
        self.connection_lost = False
        self.shared_key = b'wtf'
        self.hop_counter = 0
        self.attack_hop_threshold = 10
        self.anomaly_model = IsolationForest(contamination=0.1)  # Initialize Isolation Forest model
        self.freq_model = RandomForestRegressor()  # Initialize Random Forest model for frequency prediction
        self.features = []

    def start(self):
        self.start_switch_back_timer()
        try:
            self.current_frequency = random.randint(*self.freq_range)
            print(f"Initial frequency: {self.current_frequency}")
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('localhost', 8081))
            self.server_socket.listen(1)
            print("Server waiting for client to connect...")
            self.client_socket, _ = self.server_socket.accept()
            self.connected = True
            self.synchronize_time()  # Synchronize initially
            print(f"Server connected at frequency {self.current_frequency}")
            self.client_socket.send(str(self.current_frequency).encode())
            confirmation_msg = self.client_socket.recv(1024).decode()
            print(f"Client confirmation: {confirmation_msg}")
            threading.Thread(target=self.frequency_hopping, daemon=True).start()
        except Exception as e:
            print(f"Error in server start: {e}")
            self.connection_lost = True
    def start_switch_back_timer(self):
        self.switch_back_timer = threading.Timer(60, self.switch_back_to_original_range)
        self.switch_back_timer.start()

    def switch_back_to_original_range(self):
        print("Switching back to original frequency range")
        self.freq_range = self.original_freq_range
        self.frequency_hopping()

    def disconnect(self):
        self.connected = False
        print("Server disconnected")
        self.connection_lost = True

    # Inside Server class frequency_hopping method
    def frequency_hopping(self):
        while self.connected:
            try:
                new_frequency = random.randint(*self.freq_range)
                with self.lock:
                    print(f"Server hopping to frequency {new_frequency}")
                    self.current_frequency = new_frequency
                    encrypted_freq = self.encrypt(str(new_frequency).encode())
                    self.hop_counter += 1
                    self.client_socket.send(encrypted_freq)
                    self.features.append([new_frequency])
                # Wait for acknowledgment from client
                ack = self.client_socket.recv(1024)
                if len(self.features) >= 10:  # Update anomaly model after collecting 10 samples
                    self.update_anomaly_model()
                if ack != b"ACK":
                    print("Failed to receive acknowledgment from client.")
                    self.connection_lost = True
                    break
                if self.hop_counter == self.attack_hop_threshold:
                    self.simulate_attack()
                time.sleep(1)
            except Exception as e:
                print(f"Error in frequency hopping: {e}")
                self.connection_lost = True

    def predict_next_frequency(self):
        try:
            # Extract features for frequency prediction
            # For simplicity, assuming the features are just the previous frequency
            X = np.array([[self.current_frequency]])
            # Predict the next frequency using the machine learning model
            next_frequency = int(self.freq_model.predict(X)[0])
            # Clip the predicted frequency to the defined range
            next_frequency = max(min(next_frequency, self.freq_range[1]), self.freq_range[0])
            return next_frequency
        except Exception as e:
            print(f"Error predicting next frequency: {e}")
            return random.randint(*self.freq_range)

    def update_anomaly_model(self):
        try:
            self.anomaly_model.fit(self.features)
            self.features = []  # Reset features for the next round of sampling
        except Exception as e:
            print(f"Error updating anomaly model: {e}")
    def simulate_attack(self):
        if self.switch_back_timer:
            self.switch_back_timer.cancel()
        self.start_switch_back_timer()
        print("Simulating attack after 10 hops")
        self.attack_detected = True
        # Switch to safe frequency range
        self.switch_to_safe_range()

    def synchronize_time(self):
        try:
            ntp_client = ntplib.NTPClient()
            response = ntp_client.request('1.europe.pool.ntp.org')
            print(f"NTP Server: {response.tx_time}")
            print(f"NTP Offset: {response.offset}")
            print(f"Time before adjustment: {time.time()}")
            current_time = time.time()
            current_time += response.offset
            print(f"Time after adjustment: {current_time}")
        except Exception as e:
            print(f"NTP Error: {e}")
        threading.Timer(30, self.synchronize_time).start()

    def encrypt(self, data):
        iv = os.urandom(16)
        key = self.derive_key()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt',
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.shared_key)

    def detect_attack(self):
        if self.switch_back_timer:
            self.switch_back_timer.cancel()
        self.start_switch_back_timer()
        while self.connected:
            time.sleep(35)  # Scan for potential attacks every 2 minutes
            with self.lock:
                if not self.attack_detected:
                    # Simulate attack detection
                    if random.random() < 0.50:  # 5% chance of detecting an attack
                        print("Server detected an attack!")
                        self.attack_detected = True
                        # Switch to safe frequency range
                        self.switch_to_safe_range()

    def switch_to_safe_range(self):
        self.freq_range = (5000, 8000)
        print("Server and client switched to safe frequency range.")

    def frequency_hopping_safe_range(self):
        while self.connected and self.attack_detected:
            new_frequency = random.randint(*self.freq_range)
            with self.lock:
                print(f"Server hopping to frequency {new_frequency} within safe range")
                self.current_frequency = new_frequency
                self.client_socket.send(str(new_frequency).encode())
            time.sleep(1)


# Define frequency range
frequency_range = (500, 1000)

# Create and start the server
server = Server(frequency_range)
server.start()

# Monitor connection
while True:
    time.sleep(1)
    if server.connection_lost:
        print("Connection lost.")
        break
