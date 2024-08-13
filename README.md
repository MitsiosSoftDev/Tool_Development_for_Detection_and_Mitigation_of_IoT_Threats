# **Thesis Project - Development Of A Tool For Detection And Mitigation Of IoT Threats**

## This tool was developed by me and was the Thesis Project for my BSc Degree in Computer Science. The project was developed in Python using JetBrains - PyCharm Professional. The project is based on a Server - Client Architecture and the communication between the two programs is achieved using sockets.



## **Technologies Used** 

- *Communication Protocols and Networking*

- *Cryptography*

- *Machine Learning Models*

- *Frequency Hopping*

- *Multithreading*

- *Time Synchronization*

- *Anomaly Detection*



### **Details**

#### 1. **Communication Protocols and Networking**
   - **Sockets (TCP/IP)**: Both the server and client use Python's `socket` library to establish a TCP/IP connection on `localhost` and port `8081`. The server binds and listens for incoming connections, while the client attempts to connect to the server. The two programs communicate by sending and receiving data through this socket connection.
  
#### 2. **Cryptography**
   - **AES Encryption**: The `cryptography` library is used for data encryption and decryption. AES (Advanced Encryption Standard) in CFB (Cipher Feedback) mode is utilized to encrypt the frequency data transmitted between the server and client. The encryption ensures that the frequency data remains secure during transmission.
   - **Key Derivation**: PBKDF2 (Password-Based Key Derivation Function 2) is employed to derive a cryptographic key from a shared secret (`shared_key`) using the `PBKDF2HMAC` class. This key is used for AES encryption/decryption.
   - **Padding**: The encryption process uses PKCS7 padding to ensure the data blocks are of the correct length for encryption.

#### 3. **Machine Learning Models**
   - **Isolation Forest**: Both the server and client utilize the `IsolationForest` algorithm from the `sklearn.ensemble` module to detect anomalies in the frequency data. This model is trained with frequency samples and helps identify abnormal behavior that could signify an attack.
   - **Random Forest Regressor**: The `RandomForestRegressor` from the `sklearn.ensemble` module is used to predict the next frequency for hopping. It predicts the next frequency based on previous frequencies, aiding in dynamic frequency hopping.

#### 4. **Frequency Hopping**
   - The server and client implement a frequency hopping mechanism, where the communication frequency changes periodically to avoid interception or jamming. This is controlled by the `frequency_hopping` method in both classes.
   - **Safe Frequency Range**: Upon detecting an attack (either simulated or through anomaly detection), both the server and client switch to a pre-defined "safe frequency range" (5000 to 8000 Hz).

#### 5. **Multithreading**
   - **Threading**: The `threading` library is used to handle multiple operations simultaneously, such as frequency hopping, attack detection, and time synchronization. This allows the server and client to manage these tasks concurrently without blocking the main thread.
  
#### 6. **Time Synchronization**
   - **NTP (Network Time Protocol)**: Both the server and client synchronize their clocks using NTP. The `ntplib` library is used to fetch the current time from an NTP server (`1.europe.pool.ntp.org`). This synchronization ensures that both ends are operating on the same timeline, which is crucial for coordinated frequency hopping.

#### 7. **Security and Anomaly Detection**
   - **Attack Detection and Simulation**: The programs simulate attacks by artificially creating conditions that would be recognized as suspicious by the anomaly detection model. Upon detecting an attack, the programs switch to a "safe" frequency range and continue their operations.



### How the Programs Communicate and Work Together

- **Connection Establishment**: The server waits for a connection from the client on a specified port (`8081`). Once the client connects, the server sends the initial frequency, which is encrypted using AES. The client decrypts this frequency and sends an acknowledgment back to the server.
  
- **Frequency Hopping**: Both the server and client engage in frequency hopping to prevent unauthorized interception. The server determines a new frequency, encrypts it, and sends it to the client. The client decrypts the frequency and adjusts accordingly, sending an acknowledgment after each hop.

- **Attack Simulation and Response**: After a predefined number of hops, the server simulates an attack. Both the server and client detect this "attack" and switch to a safe frequency range. They continue to operate within this range, using the same mechanisms of encryption, decryption, and acknowledgment to maintain communication.



### Libraries and Technologies Used

- **`socket`**: For creating TCP/IP connections.
- **`threading`**: For running concurrent operations (e.g., frequency hopping, attack detection).
- **`ntplib`**: For synchronizing time using the Network Time Protocol.
- **`sklearn.ensemble`**: For machine learning models (`IsolationForest`, `RandomForestRegressor`) used in anomaly detection and frequency prediction.
- **`cryptography`**: For encryption/decryption (AES in CFB mode) and key derivation (PBKDF2HMAC).
- **`numpy`**: For handling numerical data and arrays, especially when feeding data into the machine learning models.



## User Guide of the Tool

The tool is designed to identify and mitigate potential threats to IoT devices communicating over wireless networks and consists of two main components, the Server and the Client.

Installing PyCharm:

	- Download PyCharm Community Edition (free) from the JetBrains website: https://www.jetbrains.com/pycharm/download/
	- Installation: Run the installation file and follow the instructions

PyCharm Setup:

	- Open and create two new Projects
	- In the Project Settings, select the previously installed Python Interpreter
	- Open the Server and Client Python files in PyCharm, each in the two Project Windows

Install Libraries:

	- scikit-learn (sklearn): For Machine Learning algorithms
	- ntplib: For time synchronization via NTP
	- cryptography: For data encryption

	- Cryptography for cryptography: Cryptography for cryptography, Cryptography for the cryptographic process.
	- Install libraries: Run the following commands one by one
 
	- Bash: Start from the command line (e.g. Bash, Windows, Windows XP, Windows Vista, etc.)
	- Pip install scikit-learn
	- pip install ntplib
	- pip install cryptography

Run the Tool:

	- Run Server: Right-click on the Server file and select "Run"
	- Run Client: Right-click on the Client file and select "Run"
 
 Important Remarks:

	- The tool is designed to work in a simulation environment. For use in real IoT devices, code modifications are required.
	- The effectiveness of the tool depends on the quality of the training data of the Machine Learning algorithms
 
**DISCLAIMER:**
 *Regular updating of the algorithms with new data is recommended to improve the accuracy of threat detection*
