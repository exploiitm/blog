+++
title = 'Huffing and puffing'
date = '2024-09-05'
authors = ["Achintya J"]
+++


In this we've been given a binary file, that we are supposed to exploit somehow. If we run this using IDA, we get a lot of functions. We can list down a bunch of important ones,

1. buildHuffmanTree
2. buildCodes
3. encode
4. binaryStringToInt
5. binaryStringToMatrix
6. largestPrimeFactor

It's evident that, there is huffman encoding involved! If we check out the `largestPrimeFactor` its simply giving the largest prime factor for a given number. You might try opening this with Ghidra as well,

`binaryStringToMatrix()` seems interesting 

		for (local_28 = 0; __n = local_28, (int)local_28 < (int)local_3c; local_28 = local_28 + 1) {
			this_00 = std::vector<>::operator[](&local_1f4,local_24);
			pvVar7 = std::vector<>::operator[](this_00,__n);
			std::__cxx11::to_string(*pvVar7);
			std::__cxx11::basic_string<>::operator+=((basic_string<> *)&local_218,local_f4);
			std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_f4);
		}
		binaryStringToInt(&local_218);
		this_01 = std::vector<>::operator[](&local_200,local_24);
		std::__cxx11::basic_string<>::operator=((basic_string<> *)this_01,local_dc);
		std::__cxx11::basic_string<>::~basic_string((basic_string<> *)local_dc);
		std::__cxx11::basic_string<>::~basic_string((basic_string<> *)&local_218);
	}

I got something like this, what this means is we enter a bunch of stuff in the vector `this_00`, convert binary strings to integers (which is prolly what is printing the numbers that we see on the screen). 

Now what do we know about the numbers that we are getting? We know that according to the above function each number that we get is being converted from a binary string. This means our first step should be to get the binary versions of each numbers. 

Now in the decompiled code, we can see the frequency table, (look carefully!) and we can write that in C++ as,

		std::unordered_map<char, unsigned> mp;
			mp['5'] = '1';
			mp['R'] = '1';
			mp['n'] = '1';
			mp['K'] = '1';
			mp['4'] = '1';
			mp['C'] = '1';
			mp['T'] = '2';
			mp['I'] = '2';
			mp['0'] = '1';
			mp['u'] = '1';
			mp['F'] = '1';
			mp['M'] = '1';
			mp['{'] = '1';
			mp['_'] = '1';
			mp['H'] = '1';
			mp['}'] = '1';
			mp['f'] = '2';
			mp['m'] = '1';

This means the flag contains these symbols with these frequencies. Thus, we can get a general flag as `5RnK4CTTII0uFM{_}Hffm` and why this is useful, is simply because huffman encoding gives the same encoding for "x" any other permutation of "x".

Thus, if we encode this flag, we'll get a different binary but it will have the same number of bits. But firstly, we'll have to find the binary form of the fake flag. This is because 

		#include <iostream>
		#include <string>
		#include <queue>
		#include <unordered_map>
		#include <algorithm>
		#include <bitset>
		#include <stdexcept>
		#include <vector>
		#include <fstream>
		#include <sstream>
		#include <cmath>
		using namespace std;
		struct HuffmanNode {
		    char data;
		    unsigned frequency;
		    HuffmanNode* left;
		    HuffmanNode* right;
		    HuffmanNode(char data, unsigned frequency)
		        : data(data), frequency(frequency), left(nullptr), right(nullptr) {}
		    ~HuffmanNode() {
		        delete left;
		        delete right;
		    }
		};
		struct Compare {
		    bool operator()(HuffmanNode* left, HuffmanNode* right) {
		        return left->frequency > right->frequency;
		    }
		};
		void buildCodes(HuffmanNode* root, const std::string& code, std::unordered_map<char, std::string>& codes) {
			if (!root)
				return;
			if (root->data != '\0')
				codes[root->data] = code;
			buildCodes(root->left, code + "0", codes);
			buildCodes(root->right, code + "1", codes);
			}
		HuffmanNode* buildHuffmanTree(const std::unordered_map<char, unsigned>& freqMap) {
			std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, Compare> pq;
			for (const auto& pair : freqMap) {
				pq.push(new HuffmanNode(pair.first, pair.second));
			}
			while (pq.size() != 1) {
				HuffmanNode* left = pq.top(); pq.pop();
				HuffmanNode* right = pq.top(); pq.pop();
				HuffmanNode* parent = new HuffmanNode('\0', left->frequency + right->frequency);
				parent->left = left;
				parent->right = right;
				pq.push(parent);
			}
			return pq.top();
	}
		int main(){
			std::unordered_map<char, unsigned> mp;
			mp['5'] = '1';
			mp['R'] = '1';
			mp['n'] = '1';
			mp['K'] = '1';
			mp['4'] = '1';
			mp['C'] = '1';
			mp['T'] = '2';
			mp['I'] = '2';
			mp['0'] = '1';
			mp['u'] = '1';
			mp['F'] = '1';
			mp['M'] = '1';
			mp['{'] = '1';
			mp['_'] = '1';
			mp['H'] = '1';
			mp['}'] = '1';
			mp['f'] = '2';
			mp['m'] = '1';
			std::string encoded_flag = "1773 1166 1693 1110 795 1561 115 1879";
			std::string data = "5RnK4CTTII0uFM{_}Hffm";
			HuffmanNode* root = buildHuffmanTree(mp); // build the tree
			std::unordered_map<char, std::string> codes; // build the codes
			buildCodes(root, "", codes);
			std::string encoded = encode(data, codes);
			std::cout << encoded.size();                    // this is the size

This boiler plate code is simply using ready made functions you can find on GitHub. Now, what do we know about the size?

Now in the `binaryStringToMatrix()` function we know that the binary string is being converted to a matrix and it uses the length of the binary string as the rows. The number of rows we have is the number of numbers in the encoded flag, which is 8 `1773 1166 1693 1110 795 1561 115 1879`. 

		int cols = encoded.size();
		int rows = 8;

Now we want to convert each encoded number to its binary form and then pad that to the `cols` size. For example, base2 of 317 is 100111101 which is 9 digits, but i need 11, so, i will make 317 as 00100111101... and so on for each of them. Why 11? its because the flag encoded in base2 gives 11 bits... (you can run the code to find out!)

		std::stringstream ss(encoded_flag);
		    std::vector<int> numbers;
		    std::string temp;
		    														// break the string into numbers
		    while (ss >> temp) {
		        numbers.push_back(std::stoi(temp)); // Convert to integer and store
		    }
		    std::vector<std::string> binaryStrings;														// convert to binary, pad to length 11, and store it in the binaryStrings vector
		    for (int num : numbers) {
		        std::string binary = std::bitset<11>(num).to_string();
		        binaryStrings.push_back(binary);
		    }
		/*
		   	for (const std::string &binary : binaryStrings) {													// print em
		        std::cout << binary;
		    }
		*/
		    // with this you get the huffman encoded string of the FLAG itself and you have the frequency table of the flag...
		    // 1101110110110010001110110100111011000101011001100011011110000110010000111001111101010111
		    std::string encodedString = "1101110110110010001110110100111011000101011001100011011110000110010000111001111101010111";
		    // now write the decode function and decode it using the frequency table and the encoded string to get the flag.
		    std::string flagDecoded = decodeHuffman(encodedString, root);
		    std::cout << flagDecoded;
		}

The decode function can be found online (or just ask "someone" to do it for you)

		std::string encode(const std::string& data, const std::unordered_map<char, std::string>& codes) {
		    std::string encoded;
		    for (char c : data) {
		        encoded += codes.at(c);
		    }
		    return encoded;
		}
		std::string decodeHuffman(const std::string& encodedStr, HuffmanNode* root) {
		    std::string result;
		    HuffmanNode* current = root;
		    for (char bit : encodedStr) {
		        if (bit == '0') current = current->left;
		        else current = current->right;
		        if (!current->left && !current->right) {
		            result += current->data;
		            current = root;
		        }
		    }
		    return result;
		}


So, the final code to decode is

		#include <iostream>
		#include <string>
		#include <queue>
		#include <unordered_map>
		#include <algorithm>
		#include <bitset>
		#include <stdexcept>
		#include <vector>
		#include <fstream>
		#include <sstream>
		#include <cmath>
		using namespace std;
		struct HuffmanNode {
		    char data;
		    unsigned frequency;
		    HuffmanNode* left;
		    HuffmanNode* right;
		    HuffmanNode(char data, unsigned frequency)
		        : data(data), frequency(frequency), left(nullptr), right(nullptr) {}
		    ~HuffmanNode() {
		        delete left;
		        delete right;
		    }
		};
		struct Compare {
		    bool operator()(HuffmanNode* left, HuffmanNode* right) {
		        return left->frequency > right->frequency;
		    }
		};
		void buildCodes(HuffmanNode* root, const std::string& code, std::unordered_map<char, std::string>& codes) {
		    if (!root)
		        return;
		    if (root->data != '\0')
		        codes[root->data] = code;
		    buildCodes(root->left, code + "0", codes);
		    buildCodes(root->right, code + "1", codes);
		}
		HuffmanNode* buildHuffmanTree(const std::unordered_map<char, unsigned>& freqMap) {
		    std::priority_queue<HuffmanNode*, std::vector<HuffmanNode*>, Compare> pq;
		    for (const auto& pair : freqMap) {
		        pq.push(new HuffmanNode(pair.first, pair.second));
		    }
		    while (pq.size() != 1) {
		        HuffmanNode* left = pq.top(); pq.pop();
		        HuffmanNode* right = pq.top(); pq.pop();
		        HuffmanNode* parent = new HuffmanNode('\0', left->frequency + right->frequency);
		        parent->left = left;
		        parent->right = right;
		        pq.push(parent);
		    }
		    return pq.top();
		}
		std::string encode(const std::string& data, const std::unordered_map<char, std::string>& codes) {
		    std::string encoded;
		    for (char c : data) {
		        encoded += codes.at(c);
		    }
		    return encoded;
		}
		std::string decodeHuffman(const std::string& encodedStr, HuffmanNode* root) {
		    std::string result;
		    HuffmanNode* current = root;
		    for (char bit : encodedStr) {
		        if (bit == '0') current = current->left;
		        else current = current->right;
		        if (!current->left && !current->right) {
		            result += current->data;
		            current = root;
		        }
		    }
		    return result;
		}
		int main(){
			std::unordered_map<char, unsigned> mp;
			mp['5'] = '1';
			mp['R'] = '1';
			mp['n'] = '1';
			mp['K'] = '1';
			mp['4'] = '1';
			mp['C'] = '1';
			mp['T'] = '2';
			mp['I'] = '2';
			mp['0'] = '1';
			mp['u'] = '1';
			mp['F'] = '1';
			mp['M'] = '1';
			mp['{'] = '1';
			mp['_'] = '1';
			mp['H'] = '1';
			mp['}'] = '1';
			mp['f'] = '2';
			mp['m'] = '1';
			std::string encoded_flag = "1773 1166 1693 1110 795 1561 115 1879";
			
			/*
			we know it has 8 rows (cause 8 numbers here)... How do we figure out the number of characters?
			The thing about huffman codes is, as long as the frequencies remain the same, the encoded string is the same... --> make a random string from the
			frequency table, say "5RnK4CTTII0uFM{_}Hffm", then encode it using huffman encoding
		*/
			std::string data = "5RnK4CTTII0uFM{_}Hffm";
			HuffmanNode* root = buildHuffmanTree(mp); // build the tree
			std::unordered_map<char, std::string> codes; // build the codes
		    buildCodes(root, "", codes);
		    
		    std::string encoded = encode(data, codes);
		    std::cout << encoded.size(); // Now we have the size of the encoded flag
		    int cols = encoded.size();
		    int rows = 8;
		    // now we want to convert each number in encoded_flag to its binary form and pad that to "cols" size. for example, base2 of 317 is 100111101 which is 9 digits, but i need 11
		    // so, i will make 317 as 00100111101... and so on for each of them 
		    std::stringstream ss(encoded_flag);
		    std::vector<int> numbers;
		    std::string temp;
		    														// break the string into numbers
		    while (ss >> temp) {
		        numbers.push_back(std::stoi(temp)); // Convert to integer and store
		    }
		    std::vector<std::string> binaryStrings;														// convert to binary, pad to length 11, and store it in the binaryStrings vector
		    for (int num : numbers) {
		        std::string binary = std::bitset<11>(num).to_string();
		        binaryStrings.push_back(binary);
		    }
		/*
		   	for (const std::string &binary : binaryStrings) {													// print em
		        std::cout << binary;
		    }
		*/
		    // with this you get the huffman encoded string of the FLAG itself and you have the frequency table of the flag...
		    // 1101110110110010001110110100111011000101011001100011011110000110010000111001111101010111
		    std::string encodedString = "1101110110110010001110110100111011000101011001100011011110000110010000111001111101010111";
		    // now write the decode function and decode it using the frequency table and the encoded string to get the flag.
		    std::string flagDecoded = decodeHuffman(encodedString, root);
		    std::cout << flagDecoded;
		}

--

You'll prolly realise this is brainfuckery. A lot of things are hard to read from the disassembly, but this is how its going to be in the real world! A lot of it is domain knowledge, and some intuitive feel.

There is always a way for those brave enough to find it... 
