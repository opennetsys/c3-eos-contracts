#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/crypto.h>

using namespace eosio;

class merkle: public eosio::contract {
  public:
      using contract::contract;

      ///@abi action
      void verify(const vector<std::string>& proof, std::string root, std::string leaf)
      {
        std::string computed_hash = leaf;
        auto size = proof.size();
        for (int i = 0; i < size; i++) {
          std::string proof_element = proof[i];
          checksum256 digest;
          std::string data;

          if (computed_hash < proof_element) {
            data = computed_hash + proof_element;
          } else {
            data = proof_element + computed_hash;
          }

          // FIXME: not working, this needs to be a byte array of the hex values rather than the concatenated hex string
          data = computed_hash + proof_element;

          sha256(const_cast<char*>(data.c_str()), data.size(), &digest);
          computed_hash = to_hex(digest.hash, sizeof(digest.hash));
        }

        bool valid = (computed_hash == root);
        print(" VALID: ", valid);
        print(" COMPUTED: ", computed_hash);
        print(" ROOT: ", root);
  }
};

EOSIO_ABI( merkle, (verify) )

