// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, const unsigned int *data, unsigned int count, int port)
{
     // It'll only connect to one or two seed nodes because once it connects,
     // it'll get a pile of addresses with newer timestamps.
     // Seed nodes are given a random 'last seen time' of between one and two
     // weeks ago.
     const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int k = 0; k < count; ++k)
    {
        struct in_addr ip;
        unsigned int i = data[k], t;
        
        // -- convert to big endian
        t =   (i & 0x000000ff) << 24u
            | (i & 0x0000ff00) << 8u
            | (i & 0x00ff0000) >> 8u
            | (i & 0xff000000) >> 24u;
        
        memcpy(&ip, &t, sizeof(ip));
        
        CAddress addr(CService(ip, port));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xe1;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0xb2;
        pchMessageStart[3] = 0xd4;
        vAlertPubKey = ParseHex("049fcfa264333bd32dde1d8cb6d964fa50fd807912011a2b0b4769aa7f12a8d795fa05e01722433d8215309f51df3bbdbd8b18564a847e5e54b034c8bf39a11ca2");
        nDefaultPort = 22255;
        nRPCPort = 22254;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);
/*
CBlock(hash=00000e2a6ca677f8c25d4905494710eeace49efb85d0fbf45c4233c5116a13cb, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=3a68a5f01ef81a8af3008ebedac871a38dbb5ab164f7e17f85e750d2ec192343, nTime=1466189867, nBits=1e0ffff0, nNonce=2537374, vtx=1, vchBlockSig=)
  Coinbase(hash=3a68a5f01ef81a8af3008ebedac871a38dbb5ab164f7e17f85e750d2ec192343, nTime=1466189867, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a475768792041424e20416d726f2057616e747320746f20536570617261746520426974636f696e2066726f6d2074686520426c6f636b636861696e204d61792032392c2032303136)
    CTxOut(nValue=-0.00000001, scriptPubKey=OP_DUP OP_HASH160 b472a266d0bd89c13706a4132ccfb16f7c3b9fcb OP_EQUALVERIFY OP_CHECKSIG)

  vMerkleTree:  3a68a5f01ef81a8af3008ebedac871a38dbb5ab164f7e17f85e750d2ec192343
*/
        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        int64_t nTime = 1466189867;
        const char* pszTimestamp = "Why ABN Amro Wants to Separate Bitcoin from the Blockchain May 29, 2016";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        CPubKey pubkey(ParseHex("0x04375a4e51953036ae0d91b212fb1e19c8f31cb4ba8ab24f3cfa4580ea37b7e488ad5fd0991b70fa6e7ed41f366616d4452eba1342633d610bc679fcd9493d68c1"));
        vout[0].scriptPubKey.SetDestination(pubkey.GetID());
        CTransaction txNew(1, nTime, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = nTime;
        genesis.nBits    = 0x1e0ffff0; 
        genesis.nNonce   = 2537374;

        hashGenesisBlock = genesis.GetHash();
        if (false ) {
            uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
            while (genesis.GetHash() > hashTarget)
               {
                   ++genesis.nNonce;
                   if (genesis.nNonce == 0)
                   {
                       printf("NONCE WRAPPED, incrementing time");
                       ++genesis.nTime;
                   }
               }
            printf("%s",genesis.ToString().c_str());
        }

        assert(hashGenesisBlock == uint256("0x00000e2a6ca677f8c25d4905494710eeace49efb85d0fbf45c4233c5116a13cb"));
        assert(genesis.hashMerkleRoot == uint256("0x3a68a5f01ef81a8af3008ebedac871a38dbb5ab164f7e17f85e750d2ec192343"));

        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(50);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(28);
        base58Prefixes[SECRET_KEY] =     list_of(153);
        base58Prefixes[STEALTH_ADDRESS] = list_of(40);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        vSeeds.push_back(CDNSSeedData("First",  "45.63.43.90"));
        vSeeds.push_back(CDNSSeedData("Second",  "45.63.43.122"));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        nPoolMaxTransactions = 3;
        //strSporkKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        //strMasternodePaymentsPubKey = "046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e";
        strDarksendPoolDummyAddress = "M8rBDGDe2PEhw8FCMsFAkbiUKFGDKgkELt";
        nLastPOWBlock = 1440 * 20;
        nPOSStartBlock = 0;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x2f;
        pchMessageStart[1] = 0xca;
        pchMessageStart[2] = 0x4d;
        pchMessageStart[3] = 0x3e;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("04cc24ab003c828cdd9cf4db2ebbde8e1cecb3bbfa8b3127fcb9dd9b84d44112080827ed7c49a648af9fe788ff42e316aee665879c553f099e55299d6b54edd7e0");
        nDefaultPort = 27170;
        nRPCPort = 27171;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = 1455033877; 
        genesis.nNonce = 1004377;

        //assert(hashGenesisBlock == uint256("0x00000d4d0549912423730a89e05b8f096591d32795b1612a0abd5c3541904ddf"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(97);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[STEALTH_ADDRESS] = list_of(40);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeeds(vFixedSeeds, pnTestnetSeed, ARRAYLEN(pnTestnetSeed), nDefaultPort);

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
