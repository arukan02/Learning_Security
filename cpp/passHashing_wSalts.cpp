#include <iostream>
#include <string>
#include <random>
#include <openssl/sha.h>

// Function to generate random salt
std::string generateSalt(size_t length = 16) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::default_random_engine engine(std::random_device{}());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);
    std::string salt;

    for (size_t i = 0; i < length; ++i) {
        salt += charset[dist(engine)];
    }
    return salt;
}

// Function to hash a password with a salt
std::string hashPasswordWithSalt(const std::string& password, const std::string& salt) {
    std::string saltedPassword = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)saltedPassword.c_str(), saltedPassword.size(), hash);

    std::string hashString;
    for (unsigned char c : hash) {
        hashString += "0123456789abcdef"[c >> 4];
        hashString += "0123456789abcdef"[c & 0x0F];
    }
    return hashString;
}

int main() {
    std::string password = "securepassword";
    std::string salt = generateSalt();
    std::string hash = hashPasswordWithSalt(password, salt);

    std::cout << "Password: " << password << std::endl;
    std::cout << "Salt: " << salt << std::endl;
    std::cout << "Hash: " << hash << std::endl;

    return 0;
}
