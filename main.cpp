#include "examples.h"

using namespace std;
using namespace seal;


void test_func(){
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024);
    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t array_size = 16;
    size_t subarray_size = 4;
    size_t no_of_subarrays = array_size / subarray_size;
    vector<uint64_t> input_data = { 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0 };

    // Encrypt the input data
    vector<Ciphertext> encrypted_data(array_size);
    for (size_t i = 0; i < array_size; i++) {
        Plaintext plain_input(to_string(input_data[i]));
        encryptor.encrypt(plain_input, encrypted_data[i]);
    }

    // LOCALIZATION
    // 1. Compute RS-OR
    double epsilon = pow(2, -80);
    size_t n = array_size;
    size_t N = ceil(log2(n/epsilon));
    
    vector<vector<int>> r(N, vector<int>(n));
    for (size_t i = 0; i < N; i++) {
        for (size_t j = 0; j < n; j++) {
            r[i][j] = rand() % 2;
        }
    }

    vector<Ciphertext> localized_rsor(no_of_subarrays);
    for (int i=0; i < no_of_subarrays; i++) {
        localized_rsor(encrypted_data, encryptor)
    }

    
}