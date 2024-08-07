+++ title = "Freshie Induction" date = 2024-08-06 +++

The freshers of 2024 were welcomed to an exciting session hosted by the Cybersecurity and Math Clubs. They explored the fascinating world of `cryptography`, learning about **asymmetric encryption**, **modular arithmetic**, and some **real-time code cracking**. We ensured that the participants understand cipher algorithms like **Playfair**, explore **Enigma** and discover the workings of the **Diffie-Hellman key exchange and AES**. 

The sessions covered the following topics in details:

## Bijective functions

- A key concept in encryption is the use of bijective functions. These are functions that are one-one and onto (if these terms confuse you, refer to this [link](https://byjus.com/maths/bijective-function/)). 
- We explained the need of bijective functions in order to ensure that the recipient of the cryptic message is the only person in the world who can understand it.

## Modular arithmetic

### Basics
Modular arithmetic forms the basis of many cryptosystems in the world today. The basic idea behind using this operator is the way it effectively `shifts` the plaintext in a known and understandable way, which can later be `reshifted` to get the original message back.

- We explored the idea of a `modulus` and described its __terminology__ and __mathematic properties__. We explained the effect the moduluo operator has with different examples.
- The __roll-over__ effect of a modulus was explained the idea of shifts was shown to the participants. We discussed `ROT` ciphers and had the participants break them!

The modular multiplicative inverse is an important concept which must be understood well before understanding cryptosystems like RSA. This is defined for an integer `a` and it's value is another integer `x` such that `a*x` is congruent to 1 modular some modulus `m`. 

- We talked about the conditions required for the multiplicative inverse of an integer to exist and explained the use of this special math in cryptography. 

### Fermat's Little Theorem 

To bring the participants closer to understanding RSA we introduced **Fermat's Little theorem**.

Fermat's little theorem states that if p is a prime number, then for any integer a, a^p is an integral multiple of p

### Factorising Large Primes
Freshers were asked to crack a series of numbers, by figuring out the two prime factors that make it up. To ensure that they understand how hard it actually is, we gradually increased the size of the number we were giving, until hand computation became a nightmare.


## Ciphers

Cryptography is about keeping information secret. A cipher is an algorithm that converts plaintext into some __seemingly gibberish text__. In order to get the plaintext back, a `key` is needed to decipher it back to plaintext. 

### Ceaser cipher

Ceaser cipher falls into what is called a `substitution cipher`, where every alphabet is mapped to a different alphabet (see [modular arithmetic](#Modular-arithmetic)) based on a predefined algorithm. 

There are many vulnerabilities associated with this method,
- The frequency of occurence of a letter is not changed, hence an experienced cryptanalyst can break it down without much effort (this relies on the fact that some letters in english occur more frequently than others, for more information refer this [link](https://www.101computing.net/frequency-analysis/)).
- There are only so many rotations that can be made with plain letters. A simple crack would be to go through every single mapping and stop when the text resembles English (or any other language for that matter).

### Playfair

Playfair was the first literal [digraph subsitution](https://en.wikipedia.org/wiki/Playfair_cipher) cipher. It is a symmetric cipher since the same scheme that encrpyts the plaintext is used to decrypt it. The key in the latter case is generated through a series of manipulations on the cipher text (see [this](https://www.geeksforgeeks.org/playfair-cipher-with-examples/)).

### Enigma

We also dived into the state-of-the-art `Enigma machines` which was cracked by a team of cryptanalysts led by the perhaps the most famous computer-scientist ever "Alan Turing". The enigma consisted of several rotors which swapped letters for others, but the catch being that, with every key press, the rotors changed their mapping!

This means, while encrpyting a string like "BBB" using substitution cipher would result in say "XXX", in case of enigma it becomes "XYZ"!

Apart from the rotors, the enigma also had reflectors which essentially reflect back to different pins of the rotors. Since, the circuit is unique, if we can figure out what "W" was mapped to (say "X") then, "X" would be mapped to "W".

Alan Turing was able to build the `Bombe`, a large electromagnetic device whose job as described by [Gordon Welchman](https://en.wikipedia.org/wiki/Gordon_Welchman) was simply to "bring 'further analysis' to a manageable number". 

## AES and key-exchanges

Now that the idea of substitution ciphers was clear, we wanted to explain the process of establishing the key. AES or other symmetric ciphers require that the sender encrypts the message using a `key` and the recipient decrypts it using the same (or different) key. The answer lies in `modular arithmetic` again!

### Diffie-Hellman exchange

We talked about the basics of the Diffie-Hellman key exchange protocol, which is basically a method of digital encryption which allows two parties to send over their keys through a **public** channel without fearing any adversary. 

It works thanks to the magic of modular artihmetic. For a complete description and some examples, be sure to check [this out](https://www.geeksforgeeks.org/implementation-diffie-hellman-algorithm/). 

## Conclusion

The collaborative session by the Cybersecurity and Maths Clubs for the freshers of 2024 was a resounding success. This event showcased the Cybersecurity Club's dedication to making complex topics accessible and engaging. The session left a lasting impression, igniting a passion for hacking and cracking in all who participated.