//
// Copyright (c) 2023 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef SICK_VISIONARY_SAMPLES_CRYPTOUTILS_H
#define SICK_VISIONARY_SAMPLES_CRYPTOUTILS_H
#include "botan_all.h"

/**
 * @brief Calculate the SHA-256 hash of a string
 * @param input The input string
 * @return The SHA-256 hash
 */
std::vector<uint8_t> calcSHA256Hash(const std::string &input) {
  // Create a SHA-256 hash object
  auto hash = Botan::HashFunction::create("SHA-256");

  if (!hash) {
    std::cerr << "Error creating SHA-256 hash function." << std::endl;
    return std::vector<uint8_t>();
  }

  // Update the hash with the input data
  hash->update(input);

  // Finalize the hash and obtain the result
  Botan::secure_vector<uint8_t> result = hash->final();

  // Convert the result to a hex-encoded string
  return Botan::unlock(result);
}

/**
 * @brief Encrypt data with AES-128
 * @param key The key for the encryption
 * @param iv The initialization vector
 * @param data The data to encrypt
 * @param padding Whether to use PKCS7 padding
 * @return The encrypted data
 */
std::vector<uint8_t> encryptWithAES128(const std::vector<uint8_t> &key,
                                       const std::vector<uint8_t> &iv,
                                       std::vector<uint8_t> &data, bool padding = true) {

  // Creating AES-128 cipher
  std::unique_ptr<Botan::BlockCipher> aes_cipher(Botan::BlockCipher::create("AES-128"));

  std::unique_ptr<Botan::Cipher_Mode> cbc_cipher;
  // Creating CBC mode with padding when SUL1 and without padding when SUL2
  if(padding){
    cbc_cipher = std::unique_ptr<Botan::Cipher_Mode>(Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::ENCRYPTION));
  }
  else {
    cbc_cipher = std::unique_ptr<Botan::Cipher_Mode>(Botan::get_cipher_mode("AES-128/CBC/NoPadding", Botan::ENCRYPTION));
  }
  // Setting the key and IV
  cbc_cipher->set_key(key);
  cbc_cipher->start(iv);

  // Convert std::vector to Botan::secure_vector
  Botan::secure_vector<uint8_t> secure_data(data.begin(), data.end());
  cbc_cipher->finish(secure_data);
  return Botan::unlock(secure_data);
}

/**
 * @brief Calculate the HMAC of a message
 * @param key The key for the HMAC
 * @param message The message to calculate the HMAC for
 * @return The HMAC
 */
std::vector<uint8_t> calculateHMAC(const std::vector<uint8_t> &key, const std::vector<uint8_t> &message) {

  // Create an HMAC object with SHA-256 as the hash function
  std::unique_ptr<Botan::MessageAuthenticationCode> hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");

  if (!hmac) {
    throw std::runtime_error("HMAC creation failed");
  }
  // Set the HMAC key
  hmac->set_key(key);

  // Update the HMAC with the message
  hmac->update(message);
  // Finalize the HMAC and obtain the result
  Botan::secure_vector<uint8_t> result = hmac->final();

  // Convert the result to a vector of uint8_t
  std::vector<uint8_t> hmacResult(result.begin(), result.end());
  return hmacResult;
}

/**
 * @brief Append a string to a vector of bytes
  * @param bytes The vector to append to
  * @param str The string to append
  */
void appendStringtoBytes(std::vector<uint8_t> &bytes, std::string str) {
  for (size_t i = 0; i < str.size(); ++i) {
    bytes.insert(bytes.end(), static_cast<uint8_t>(str[i]));
  }
}

/**
 * @brief Generate a vector of random bytes
 * @param numBytes The number of bytes to generate
 * @return A vector of random bytes
 */
std::vector<uint8_t> generateRandomBytes(uint16_t numBytes) {
  // create a vector with random bytes
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> distribution(0, 255);

  std::vector<uint8_t> randByteVector(numBytes);
  for (size_t i = 0; i < numBytes; ++i) {
    randByteVector[i] = distribution(gen);
  }
  return randByteVector;
}
#endif //SICK_VISIONARY_SAMPLES_CRYPTOUTILS_H
