#include "SMWrapper.h"
#include <iostream>

int main() {
    std::string data = "testData";

    SMWrapper::SM2Wrapper mysm2;
    std::string sm2_sig = mysm2.sign(data);
    assert (mysm2.verify(sm2_sig, data));

    while (std::cin >> data) {
        SMWrapper::SM3Wrapper mysm3;
        std::string sm3_hash = mysm3.hash(data);
        for (char& c : sm3_hash.substr(0, 2)) {
            std::cout << (int)c << " ";
        }
        std::cout << "\n";
    }

    SMWrapper::SM4Wrapper mysm4;
    std::string sm4_cipher = mysm4.encrypt(data);
    std::string sm4_text = mysm4.decrypt(sm4_cipher);
    assert (sm4_text.substr(0, data.size()) == data);

}