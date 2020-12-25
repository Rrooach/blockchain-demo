#ifndef __SM_WRAPPER__
#define __SM_WRAPPER__

#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <string>
#include <cstring>
#include <cinttypes>
#include <cassert>
#include <cstdlib>

extern "C" {
    #include "sm3.h"
    #include "sm4.h"
}

#define NO_COPY_MOVE(name) \
    name (const name&) = delete; \
    name& operator= (const name&) = delete; \
    name (name&&) = delete; \
    name& operator= (name&&) = delete

#define ALLOC_SET(type, name, count) \
    name = static_cast<type*> (malloc(count * sizeof(type)))

#define ALLOC_DEF(type, name, count) \
    type* ALLOC_SET (type, name, count)

namespace SMWrapper {

    class SM2Wrapper {
    private:
        EC_KEY* key;
        uint32_t sigMaxSize;
    public:
        SM2Wrapper (EC_KEY* _key = nullptr);
        ~SM2Wrapper ();
        NO_COPY_MOVE (SM2Wrapper);

        std::string sign (const std::string& text) const;
        bool verify (const std::string& signature, const std::string& text) const;
    };

    class SM3Wrapper {
    public:
        SM3Wrapper ();
        NO_COPY_MOVE (SM3Wrapper);

        std::string hash (const std::string& text) const;
    };

    class SM4Wrapper {
    private:
        sm4_context ctx;
        uint8_t key[16];
    public:
        SM4Wrapper (const uint8_t* _key = nullptr);
        NO_COPY_MOVE (SM4Wrapper);

        std::string encrypt (const std::string& text);
        std::string decrypt (const std::string& cipher);
    };

}

#endif