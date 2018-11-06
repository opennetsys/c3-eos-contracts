#include <eosiolib/eosio.hpp>
#include <eosiolib/print.hpp>
#include <eosiolib/crypto.h>

using namespace eosio;

template<typename CharT>
static std::string to_hex(const CharT* d, uint32_t s) {
  std::string r;
  const char* to_hex="0123456789abcdef";
  uint8_t* c = (uint8_t*)d;
  for( uint32_t i = 0; i < s; ++i ) {
    (r += to_hex[(c[i] >> 4)]) += to_hex[(c[i] & 0x0f)];
  }
  return r;
}

std::string hex_to_string(const std::string& input) {
  static const char* const lut = "0123456789abcdef";
  size_t len = input.length();
  if (len & 1) abort();
  std::string output;
  output.reserve(len / 2);
  for (size_t i = 0; i < len; i += 2) {
    char a = input[i];
    const char* p = std::lower_bound(lut, lut + 16, a);
    if (*p != a) abort();
    char b = input[i + 1];
    const char* q = std::lower_bound(lut, lut + 16, b);
    if (*q != b) abort();
    output.push_back(((p - lut) << 4) | (q - lut));
  }
  return output;
}

class merklecheckpoint: public eosio::contract {
  public:
      using contract::contract;

      /// @abi table checkpoint i64
      struct checkpoint {
        uint64_t id; // primary key
        std::string root; // merkle root

        uint64_t primary_key() const { return id; }
        uint64_t by_checkpoint_id() const { return id; }

        EOSLIB_SERIALIZE(checkpoint, (id)(root));
      };

      typedef multi_index<N(checkpoint), checkpoint, indexed_by<N(byroot), const_mem_fun<checkpoint, uint64_t, &checkpoint::by_checkpoint_id>>> checkpoints_table;

      ///@abi action
      void chkpointroot(std::string root) {
        require_auth(_self);

        checkpoints_table _checkpoints(_self, _self);

        bool exists = false;
        for (auto iter = _checkpoints.begin(); iter != _checkpoints.end(); iter++) {
          if ((*iter).root == root) {
            exists = true;
          }
        }

        if (!exists) {
          _checkpoints.emplace(_self, [&](auto &row) {
              row.id = _checkpoints.available_primary_key();
              row.root = root;
              });
        } else {
          abort();
        }
      }

      ///@abi action
      void getchkpoints() {
        checkpoints_table _checkpoints(_self, _self);

        for (auto iter = _checkpoints.begin(); iter != _checkpoints.end(); iter++) {
          print("id: ", (*iter).id);
          print("root: ", (*iter).root);
        }
      }

      ///@abi action
      void ecverify(const vector<std::string>& proof, const vector<std::uint8_t>& positions, std::string root, std::string leaf) {
        std::string computed_hash = leaf;
        uint8_t hashlen = 32;

        auto size = proof.size();
        for (int i = 0; i < size; i++) {
          std::string proof_element = proof[i];
          std::string tmp;
          checksum256 digest;
          char data[64];

          char computed_hash_char[hashlen];
          tmp = hex_to_string(computed_hash.c_str());
          memcpy(computed_hash_char, tmp.c_str(), hashlen);

          char proof_element_char[hashlen];
          tmp = hex_to_string(proof_element.c_str());
          memcpy(proof_element_char, tmp.c_str(), hashlen);

          if (positions[i] == 1) {
            memcpy(data, computed_hash_char, hashlen);
            memcpy(data+hashlen, proof_element_char, hashlen);
          } else {
            memcpy(data, proof_element_char, hashlen);
            memcpy(data+hashlen, computed_hash_char, hashlen);
          }

          sha256(data, sizeof(data), &digest);
          computed_hash = to_hex(digest.hash, sizeof(digest.hash));
        }

        bool valid = (computed_hash == root);
        print("VALID: ", valid);
  }
};

EOSIO_ABI( merklecheckpoint, (ecverify)(getchkpoints)(chkpointroot) )
