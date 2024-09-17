# C Authentication Script with OpenSSL

This is a simple C authentication program that securely stores a username and password using OpenSSL's cryptographic functions. The password is salted and hashed using SHA-256 and saved to a file. The program allows a user to register and log in by verifying the stored credentials.

## Features
- Secure password hashing with a random salt.
- Password storage and authentication using OpenSSL.
- Command-line interface for user registration and authentication.

## Requirements
- **GCC** (MinGW for Windows or any other C compiler)
- **OpenSSL** (for cryptography)

### Windows Setup

1. **Install MinGW or MSYS2:**
   - Install [MinGW](https://sourceforge.net/projects/mingw/) or [MSYS2](https://www.msys2.org/) to compile the C program.

2. **Install OpenSSL:**
   - Download OpenSSL for Windows from [here](https://slproweb.com/products/Win32OpenSSL.html) and install it.

3. **Add OpenSSL to PATH:**
   - Make sure OpenSSL's `bin` folder is added to the system's environment `PATH`.

4. **Download and Compile the Code:**
   ```bash
   gcc -o auth auth.c -IC:\OpenSSL-Win64\include -LC:\OpenSSL-Win64\lib -lssl -lcrypto
   ```
5. **Make Sure DLLs Are Accessible:**
    - Copy the OpenSSL DLL files (`libssl-1_1-x64.dll` and `libcrypto-1_1-x64.dll`) from the `C:\OpenSSL-Win64\bin` directory to the same directory as your compiled executable or ensure they are in the system `PATH`.

## Linux/Mac Setup

1. **Install GCC:**

    ```bash
    sudo apt-get install build-essential   # For Debian-based distros
    sudo yum groupinstall "Development Tools"   # For Red Hat-based distros
    ```
    
2. **Install OpenSSL:**

    ```bash
    sudo apt-get install libssl-dev   # For Debian-based distros
    sudo yum install openssl-devel    # For Red Hat-based distros
    ```

3. **Compile the Code:**

    ```bash
    gcc -o auth auth.c -lssl -lcrypto
    ```

## Usage

**Registration**

1. Run the program to register a user:

    ```bash
    ./auth
    ```

2. Enter a username and password when prompted.

    The credentials will be securely stored in a file `credentials.bin`.

**Login**

1. After registering, run the program again to log in:

    ```bash
    ./auth
    ```

2. Enter the username and password.

3. The program will verify the credentials and confirm whether the login was successful.

## How It Works

- **Salt Generation:** A random 16-byte salt is generated for each user.
- **Password Hashing:** The password is hashed using SHA-256 along with the salt.
- **Secure Storage:** The username, salt, and hash are stored in a binary file credentials.bin.
- **Authentication:** To log in, the program verifies the provided credentials against the stored data.

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE). file for details.

### Explanation of Sections:
- **Requirements**: Lists dependencies such as GCC and OpenSSL.
- **Setup Instructions**: Provides platform-specific instructions for setting up the environment.
- **Usage**: Explains how to register and log in using the program.
- **How It Works**: Describes the process of how the script handles authentication.
- **License**: Placeholder for the project’s license (e.g., MIT).