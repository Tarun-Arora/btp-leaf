#include "seal/seal.h"

using namespace seal;

int main()
{
    // Create a SEAL context and set the encryption parameters
    EncryptionParameters parms;
    parms.set_poly_modulus("1x^4096 + 1");
    parms.set_coeff_modulus(coeff_modulus_128(4096));
    parms.set_plain_modulus(256);

    SEALContext context(parms);

    // Create an encryptor and decryptor object
    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);

    // Encrypt some data
    int data = 42;
    Plaintext plain_data(to_string(data));
    Ciphertext encrypted_data;
    encryptor.encrypt(plain_data, encrypted_data);

    // Perform a homomorphic operation on the encrypted data
    Evaluator evaluator(context);
    Ciphertext squared_data;
    evaluator.square(encrypted_data, squared_data);

    // Decrypt the result
    Plaintext plain_result;
    decryptor.decrypt(squared_data, plain_result);
    cout << "Result: " << plain_result.to_string() << endl;

    return 0;
}