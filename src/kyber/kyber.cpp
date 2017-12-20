// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include "kyber.h"

Kyber::Kyber()
{
    _pk.resize(KYBER_PUBLICKEYBYTES, 0);
    _sk.resize(KYBER_SECRETKEYBYTES, 0);

    crypto_kem_keypair(_pk.data(), _sk.data());
}

bool Kyber::kem_encode(const std::vector<uint8_t> &other_pk)
{
    // TODO: Verify sizes (other_pk)

    _key.resize(KYBER_SYMBYTES);
    _ct.resize(KYBER_CIPHERTEXTBYTES);

    crypto_kem_enc(_ct.data(),
                   _key.data(),
                   other_pk.data());
}

bool Kyber::kem_decode(const std::vector<uint8_t> &cyphertext)
{
    // TODO: Verify sizes (other_pk)
    _key.resize(KYBER_SYMBYTES);

    auto validation_error = crypto_kem_dec(_key.data(),
                                           cyphertext.data(),
                                           _sk.data());

    return validation_error == 0;
}
