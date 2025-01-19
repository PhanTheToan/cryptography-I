#include <bits/stdc++.h>

using namespace std;

// Hàm chuyển đổi từ chuỗi hexa sang vector các byte (uint8_t)
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16); // Ex: "31"->"0x31"
        bytes.push_back(byte);
    }
    return bytes;
}

// Hàm tạo ánh xạ XOR có thể xảy ra giữa các cặp ký tự trong chuỗi
unordered_map<int, vector<pair<int, int>>> possible_xor_results(const string& charset) {
    unordered_map<int, vector<pair<int, int>>> res;
    for (size_t i = 0; i < charset.size(); ++i) {
        for (size_t j = i + 1; j < charset.size(); ++j) {
            int a = charset[i];
            int b = charset[j];
            res[a ^ b].push_back(make_pair(a, b));
        }
        res[0].push_back(make_pair(charset[i], charset[i]));  // XOR của một ký tự với chính nó là 0
    }
    return res;
}

int main() {
    // Dữ liệu bản mã
    vector<string> hex_ciphertexts = {
        "315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba50",
        "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb741",
        "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de812",
        "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee41",
        "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de812",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d",
        "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af513",
        "315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e941",
        "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f404",
        "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d",
        "32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904" // target
    };

    vector<vector<uint8_t>> ciphertexts;
    for (const auto& hex_str : hex_ciphertexts) {
        ciphertexts.push_back(hex_to_bytes(hex_str));
    }// Chuyen ve dang 0x

    // Tạo các cặp XOR có thể
    string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    auto possible_xor_pairs = possible_xor_results(charset); // Luu gia Xor co the 

    // Khởi tạo mảng lưu trữ các khóa có thể
    vector<unordered_map<int, int>> possible_keys(ciphertexts[0].size()); // Gs khoa co do dai ban dau = ciphertexts 0

    // Duyệt qua từng cặp bản mã
    for (size_t i = 0; i < ciphertexts.size(); ++i) {
        for (size_t j = i + 1; j < ciphertexts.size(); ++j) {
            const auto& c1 = ciphertexts[i]; // Cipertexti
            const auto& c2 = ciphertexts[j]; // Cipertexti+1
            //Xor tung ciphertext voi nhau va khong lap lai
            for (size_t k = 0; k < c1.size(); ++k) { // Tai byte thu k
                set<int> possible_cipher_chars;
                int b1 = c1[k], b2 = c2[k];
                int xor_val = b1 ^ b2;
                if (possible_xor_pairs.count(xor_val)) { // Neu thuoc [a-z,A-Z,0]
                    for (const auto& p : possible_xor_pairs[xor_val]) {
                        possible_cipher_chars.insert(b1 ^ p.first);
                        possible_cipher_chars.insert(b1 ^ p.second);
                    }
                }
                for (int c : possible_cipher_chars) {
                    possible_keys[k][c]++; // so lan xuat hien cua ki tu "int c" tai vi tri k , p.first la vi tri K, p.second la gia tri Key co the
                }
            }
        }
    }

    // Đoán khóa dựa trên số lần xuất hiện nhiều nhất
    vector<int> key_guess(ciphertexts[0].size());

    for (size_t i = 0; i < possible_keys.size(); ++i) {// truy nhap phan tu thu i cua ds possible_key
        int max_count = 0;
        for (const auto& p : possible_keys[i]) { // Trong unordermap[i], xet cac p , tim p.second max roi luu vao key_guess
            if (p.second > max_count) {
                key_guess[i] = p.first;
                max_count = p.second;
            }
        }
    }

    // Giải mã từng bản mã với khóa dự đoán
    for (size_t i = 0; i < ciphertexts.size(); ++i) {
        cout << i + 1 << " | ";
        for (size_t j = 0; j < ciphertexts[i].size(); ++j) {
            char plaintext_char = ciphertexts[i][j] ^ key_guess[j];
            if (isprint(plaintext_char)) {
                cout << plaintext_char;
            } else {
                cout << '?'; // nếu không in được thì thay bằng '?'
            }
        }
        cout << endl;
    }

    return 0;
}
