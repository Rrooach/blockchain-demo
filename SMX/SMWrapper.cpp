#include "SMWrapper.h"

namespace SMWrapper {

// SM2

SM2Wrapper::SM2Wrapper (EC_KEY* _key) {
    if (_key) {
        key = _key;
    } else {
        key = EC_KEY_new();
        assert (key);

        size_t cnt = EC_get_builtin_curves(NULL, 0);
        ALLOC_DEF (EC_builtin_curve, curves, cnt);
        EC_get_builtin_curves(curves, cnt);

        int nid = curves[20].nid; // 20 can be change
        EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
        free(curves);
        assert (group);

        assert (EC_KEY_set_group(key, group) == 1);
        EC_GROUP_free(group);

        assert (EC_KEY_generate_key(key) == 1);

        assert (EC_KEY_check_key(key) == 1);
    }
    sigMaxSize = ECDSA_size(key);
}

SM2Wrapper::~SM2Wrapper () {
    EC_KEY_free(key);
}

std::string SM2Wrapper::sign (const std::string& text) const {
    ALLOC_DEF (uint8_t, sig, sigMaxSize);
    uint32_t sigSize;
    assert (ECDSA_sign(0, 
        reinterpret_cast<const uint8_t*> (text.c_str()), text.size(), 
        sig, &sigSize, 
    key) == 1);
    std::string ret(sig, sig + sigSize);
    free(sig);
    return ret;
}

bool SM2Wrapper::verify (const std::string& signature, const std::string& text) const {
    int ret = ECDSA_verify(0, 
        reinterpret_cast<const uint8_t*> (text.c_str()), text.size(), 
        reinterpret_cast<const uint8_t*> (signature.c_str()), signature.size(),
    key);
    assert (ret != -1);
    return ret == 1;
}

// SM3

SM3Wrapper::SM3Wrapper () {}

std::string SM3Wrapper::hash (const std::string& text) const {
    uint8_t input[text.size()], output[32];
    memcpy(input, text.c_str(), text.size());
    sm3(input, text.size(), output);
    return std::string(output, output + 32);
}

// SM4

SM4Wrapper::SM4Wrapper (const uint8_t* _key) {
    if (_key) {
        memcpy(key, _key, 16);
    } else {
        uint8_t defaultKey[16] = {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98,
            0x76, 0x54, 0x32, 0x10
        };
        memcpy(key, defaultKey, 16);
    }
}

std::string SM4Wrapper::encrypt (const std::string& text) {
    int32_t textSize = (text.size() + 15) / 16 * 16;
    uint8_t input[textSize], output[textSize];
    memcpy(input, reinterpret_cast<const uint8_t*> (text.c_str()), text.size());
    for (size_t i = text.size(); i < textSize; ++i) {
        input[i] = 0;
    }
    sm4_setkey_enc(&ctx, key);
    sm4_crypt_ecb(&ctx, SM4_ENCRYPT, textSize, input, output);
    return std::string(output, output + textSize);
}

std::string SM4Wrapper::decrypt (const std::string& cipher) {
    int32_t cipherSize = (cipher.size() + 15) / 16 * 16;
    assert (cipherSize == cipher.size());
    uint8_t input[cipherSize], output[cipherSize];
    memcpy(input, reinterpret_cast<const uint8_t*> (cipher.c_str()), cipher.size());
    for (size_t i = cipher.size(); i < cipherSize; ++i) {
        input[i] = 0;
    }
    sm4_setkey_dec(&ctx, key);
    sm4_crypt_ecb(&ctx, SM4_DECRYPT, cipherSize, input, output);
    return std::string(output, output + cipherSize);
}

}