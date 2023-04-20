#include "helper.h"

using namespace std;
using namespace seal;

string return_decrypted_value(Decryptor &decryptor, Ciphertext rs_or_encrypted)
{
    Plaintext rs_or_plain;
    decryptor.decrypt(rs_or_encrypted, rs_or_plain);
    return rs_or_plain.to_string();
}

Ciphertext return_flip_ciphertext(Evaluator &evaluator, Ciphertext &val)
{
    Ciphertext temp = val;
    evaluator.negate_inplace(temp);
    evaluator.add_plain_inplace(temp, Plaintext("1"));
    return temp;
}

void leaf_example()
{
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192*2;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 50, 50, 60, 60 }));
    parms.set_plain_modulus(2);
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
    // BatchEncoder encoder(context);

    size_t array_size = 16;
    size_t subarray_size = 4;
    size_t no_of_subarrays = array_size / subarray_size;
    vector<uint64_t> v = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0};
    
    cout << "Input Array: ";
    for(auto i: v) cout << i <<" ";
    cout << "\n\n";

    cout << "Started LEAF Algorithm\n";

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
        }
    }

    Ciphertext zero;
    encryptor.encrypt_zero(zero);
    
    Plaintext plaintext1("1");
    Ciphertext ciphertext1;
    encryptor.encrypt(plaintext1, ciphertext1);
    
    vector<Ciphertext> p;
    Ciphertext prod, temp_ct;
    vector<Ciphertext> localized_rsor(no_of_subarrays);
    for (int subarray_no = 0; subarray_no < no_of_subarrays; subarray_no++)
    {
        p = vector<Ciphertext> (N, zero);
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

                evaluator.add_inplace(p[j], prod);
            }
        }
        // At this step, for this prefix of this subarray 
        // we would have p[0] to p[N-1], so RS-OR would be 1-product of complement of all p
        prod = return_flip_ciphertext(evaluator, p[0]);
        for(int i=1; i < N; i++){
            evaluator.multiply_inplace(prod, return_flip_ciphertext(evaluator, p[i]));
            evaluator.relinearize_inplace(prod, relin_keys);
        }

        localized_rsor[subarray_no] = return_flip_ciphertext(evaluator, prod);
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

    vector<Ciphertext> fin(subarray_size, zero);
    for(int i = 0; i < subarray_size; i++){
        for(int j = 0; j < no_of_subarrays; j++){
            evaluator.add_inplace(fin[i], shield[i + j * subarray_size]);
        }
    }
    
    for(int i = 1; i < subarray_size; i++){
        evaluator.multiply(fin[i], fin[i-1], temp_ct);
        evaluator.negate_inplace(temp_ct);
        evaluator.add_inplace(fin[i], fin[i-1]);
        evaluator.add_inplace(fin[i], temp_ct);
    }

    for(int i = subarray_size - 1; i > 0; i--){
        temp_ct = fin[i - 1];
        evaluator.negate_inplace(temp_ct);
        evaluator.add_inplace(fin[i], temp_ct);
    }

    vector<Ciphertext> ex_v(array_size);
    for(int i = 0; i < array_size; i++){
        ex_v[i] = fin[i % subarray_size];
        evaluator.multiply_inplace(ex_v[i], shield[i]);
    }

    Ciphertext temp_ct1 = zero; 
    size_t k = ceil(log2(array_size + 1));
    int output = 0; 
    int temp_int;
    Plaintext temp_plain;

    parms.set_plain_modulus(40961);
    context = SEALContext(parms);
    for(int i = 0; i < k; i++) {
        temp_ct = zero;
        for(int j = 1; j <= array_size; j++) {
            temp_int = (j >> (k - i - 1)) % 2;
            if (temp_int){
                evaluator.multiply_plain(ex_v[j-1], Plaintext(to_string(temp_int)), temp_ct1);
                evaluator.add_inplace(temp_ct, temp_ct1);
            }
        }
        decryptor.decrypt(temp_ct, temp_plain);
        output = 2 * output + (temp_plain.to_string() == "1");
    }
    cout << "Position of first '1' in the input array: ";
    cout << output << "\n";
}