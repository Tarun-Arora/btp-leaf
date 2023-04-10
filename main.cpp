#include "examples.h"

using namespace std;
using namespace seal;

void print_decrypted_value(Decryptor &decryptor, Ciphertext &rs_or_encrypted)
{
    Plaintext rs_or_plain;
    decryptor.decrypt(rs_or_encrypted, rs_or_plain);
    cout << rs_or_plain.to_string() << "\n";
}

void test_func()
{
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(40961);
    SEALContext context(parms);

    // if (chain_size < 2) {
    //     // Automatically generate new parameters with a larger chain
    //     context.auto_relin_params();
    // }

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    GaloisKeys gal_keys;
    keygen.create_galois_keys(vector<uint32_t>{ 1 }, gal_keys);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    size_t array_size = 16;
    size_t subarray_size = 4;
    size_t no_of_subarrays = array_size / subarray_size;
    vector<uint64_t> v = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0};

    // Encrypt the input data
    vector<Ciphertext> encrypted_data(array_size);
    for (size_t i = 0; i < array_size; i++)
    {
        Plaintext plain_input(to_string(v[i]));
        encryptor.encrypt(plain_input, encrypted_data[i]);
    }

    // LOCALIZATION
    // double epsilon = pow(2, -80);
    double epsilon = 0.1;
    size_t N = ceil(log2(array_size / epsilon));
    vector<vector<uint64_t>> r(N, vector<uint64_t>(array_size));
    for (int i = 0; i < N; i++)
    {
        for (int j = 0; j < array_size; j++)
        {
            r[i][j] = rand() % 2;
            // cout << r[i][j] << " ";
        }
        // cout << "\n";
    }

    Ciphertext zero;
    encryptor.encrypt_zero(zero);
    
    Plaintext plaintext1("1");
    Ciphertext ciphertext1;
    encryptor.encrypt(plaintext1, ciphertext1);
    
    vector<Ciphertext> p(N, zero);
    Ciphertext prod, temp_ct;
    vector<Ciphertext> localized_rsor(no_of_subarrays);
    for (int subarray_no = 0; subarray_no < subarray_size; subarray_no++)
    {
        for (int j = 0; j < N; j++)
        {
            for (int index_in_subarray = 0; index_in_subarray < subarray_size; index_in_subarray++)
            {
                int i = 4 * subarray_no + index_in_subarray;
                // p[j] = (p[j] + r[j][i] * v[i]) % 2;
                prod = zero;
                vector<uint64_t> vec{r[j][i]};
                Plaintext temp(to_string(r[j][i]));
                if (r[j][i] != 0)
                    evaluator.multiply_plain(encrypted_data[i], temp, prod);

                evaluator.add(p[j], prod, p[j]);

                // TODO: SOMEHOW CARRY OUT p[j]%2 or p[j]&1
                // print_decrypted_value(decryptor, p[j]);
                // Plaintext plaintext1("1");
                // // Ciphertext ciphertext1;
                // // encryptor.encrypt(plaintext1, ciphertext1);
                // evaluator.multiply_plain_inplace(p[j], plaintext1);
                // print_decrypted_value(decryptor, p[j]);
            }
        }
        // At this step, for this prefix of this subarray 
        // we would have p[0] to p[N-1], so RS-OR would be 1-product of complement of all p
        evaluator.negate(p[0], temp_ct);
        evaluator.add_plain_inplace(temp_ct, ciphertext1);
        prod = temp_ct;
        for(int i=1; i < N; i++){
            evaluator.negate(p[i], temp_ct);
            evaluator.add_plain_inplace(temp_ct, ciphertext1);
            evaluator.multiply_inplace(prod, temp_ct);
        }

        evaluator.negate_inplace(prod);
        evaluator.add_plain_inplace(prod, ciphertext1);
        localized_rsor[subarray_no] = prod;
    }

    vector<Ciphertext> localized_rsor_copy(localized_rsor);
    for(int i = 1; i < no_of_subarrays; i++){
        temp_ct = localized_rsor_copy[i-1];
        evaluator.negate_inplace(temp_ct);
        evaluator.add(localized_rsor_copy[i], temp_ct, localized_rsor[i]);
    }

    vector<Ciphertext> shield(array_size);
    for(int i=0;i<array_size;i++){
        shield[i] = localized_rsor[i/4];
        evaluator.multiply_inplace(shield[i], encrypted_data[i]);
    }

    vector<Ciphertext> fin(subarray_size, zero)
    for(int i = 0; i < subarray_size; i++){
        for(int j = 0; j < no_of_subarrays; j++){
            evaluator.add_inplace(fin[i], shield[i + j * subarray_size]);
        }
    }

}