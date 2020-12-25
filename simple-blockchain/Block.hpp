//author: tko
#ifndef BLOCK_H
#define BLOCK_H

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>

#include "json.hh"
using json = nlohmann::json;

#include "../SMX/SMWrapper.h"

class Block {
    public:
        Block(int index, string prevHas, string hash, string nonce, vector<string> data, SMWrapper::SM4Wrapper& sm4Wrapper, SMWrapper::SM2Wrapper& sm2Wrapper);
        string getPreviousHash(void);
        string getHash(void);
        int getIndex(void);
        vector<string> getData(SMWrapper::SM4Wrapper& sm4Wrapper, SMWrapper::SM2Wrapper& sm2Wrapper);

        void toString(void);
        json toJSON(void);
    private:
        int index;
        string previousHash;
        string blockHash;
        string nonce;
        vector<string> data;
        string dataSig;
        // string getMerkleRoot(const vector<string> &merkle);
};
// Constructor 
Block::Block(int index, string prevHash, string hash, string nonce, vector<string> data, SMWrapper::SM4Wrapper& sm4Wrapper, SMWrapper::SM2Wrapper& sm2Wrapper ) {
    printf("\nInitializing Block: %d ---- Hash: %s \n", index,hash.c_str());
    this -> previousHash = prevHash;
    string fullS;
    for (std::string& s : data) {
        string sext = s;
        while (sext.size() % 16 != 0) sext += '\0';
        this->data.push_back(sm4Wrapper.encrypt(sext));
        fullS += sext;
    }
    this -> dataSig = sm2Wrapper.sign(fullS);
    this -> index = index;
    this -> nonce = nonce;
    this -> blockHash = hash;
    
}

int Block::getIndex(void) {
    return this -> index;
}

string Block::getPreviousHash(void) {
    return this -> previousHash;
}

string Block::getHash(void) {
    return this -> blockHash;
}

vector<string> Block::getData(SMWrapper::SM4Wrapper& sm4Wrapper, SMWrapper::SM2Wrapper& sm2Wrapper){
    vector<string> ret;
    string fullS;
    for (const string& s : data) {
        string tmp = sm4Wrapper.decrypt(s);
        ret.push_back(tmp);
        fullS += tmp;
    }
    assert (sm2Wrapper.verify(this->dataSig, fullS));
    return ret;
}

// Prints Block data 
void Block::toString(void) {
    string dataString;
    for (int i=0; i < data.size(); i++)
        dataString += data[i] + ", ";
    printf("\n-------------------------------\n");
    printf("Block %d\nHash: %s\nPrevious Hash: %s\nContents: %s",
        index,this->blockHash.c_str(),this->previousHash.c_str(),dataString.c_str());
    printf("\n-------------------------------\n");
}


json Block::toJSON(void) {
    json j;
    j["index"] = this->index;
    j["hash"] = this->blockHash;
    j["previousHash"] = this->previousHash;
    j["nonce"] = this->nonce;
    j["data"] = this->data;
    return j;
}


#endif