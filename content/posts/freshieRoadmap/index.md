+++
title = "Freshie Roadmap" 
date = 2024-08-06 
+++



The freshers of 2024 were welcomed to an exciting session hosted by the Cybersecurity and Math Clubs. They explored the fascinating world of cryptography, learning about asymmetric encryption, modular arithmetic, and some real-time code cracking. We ensured that the participants understood cipher algorithms like Playfair, explored Enigma, and discovered the workings of the Diffie-Hellman key exchange and AES.

{{ img(id="image1.jpeg", alt="Alt Text", class="textCenter") }}

The sessions covered the following topics in detail:

### Bijective Functions

A key concept in encryption is the use of bijective functions. These are functions that are one-one and onto. We explained the need for bijective functions to ensure that the recipient of the cryptic message is the only person who can understand it.

### Modular Arithmetic Basics

Modular arithmetic forms the basis of many cryptosystems today. The basic idea behind using this operator is the way it effectively shifts the plaintext in a known and understandable way, which can later be reshuffled to get the original message back.

We explored the idea of a modulus and described its terminology and mathematical properties. We explained the effect the modulus operator has with different examples. The roll-over effect of a modulus was explained, and the idea of shifts was shown to the participants. We discussed ROT ciphers and had the participants break them!

The modular multiplicative inverse is an important concept that must be understood well before understanding cryptosystems like RSA. This is defined for an integer $a$, and its value is another integer $x$ such that $a \cdot x \equiv 1 \ (\text{mod} \ m)$.

We talked about the conditions required for the multiplicative inverse of an integer to exist and explained the use of this special math in cryptography.

### Fermat's Little Theorem

To bring the participants closer to understanding RSA, we introduced Fermat's Little Theorem.

Fermat's Little Theorem states that if $p$ is a prime number, then for any integer $a$, $a^p \equiv a \ (\text{mod} \ p$).

### Factorizing Large Primes

Freshers were asked to crack a series of numbers by figuring out the two prime factors that make them up. To ensure they understood how hard it actually is, we gradually increased the size of the number we were giving until hand computation became a nightmare.

### Ciphers

Cryptography is about keeping information secret. A cipher is an algorithm that converts plaintext into seemingly gibberish text. In order to get the plaintext back, a key is needed to decipher it.

{{ img(id="image2.jpeg", alt="Alt Text", class="textCenter") }}

#### Caesar Cipher

The Caesar cipher falls into what is called a substitution cipher, where every alphabet is mapped to a different alphabet based on a predefined algorithm.

There are many vulnerabilities associated with this method:

- The frequency of occurrence of a letter is not changed, hence an experienced cryptanalyst can break it down without much effort (this relies on the fact that some letters in English occur more frequently than others).
- There are only so many rotations that can be made with plain letters. A simple crack would be to go through every single mapping and stop when the text resembles English (or any other language for that matter).

#### Playfair

Playfair was the first literal digraph substitution cipher. It is a symmetric cipher since the same scheme that encrypts the plaintext is used to decrypt it. The key in the latter case is generated through a series of manipulations on the ciphertext.

#### Enigma

We also dived into the state-of-the-art Enigma machines, which were cracked by a team of cryptanalysts led by the perhaps most famous computer scientist ever, Alan Turing. The Enigma consisted of several rotors that swapped letters for others, but the catch was that, with every key press, the rotors changed their mapping!

This means, while encrypting a string like "BBB" using a substitution cipher would result in, say, "XXX", in the case of Enigma it becomes "XYZ"!

Apart from the rotors, the Enigma also had reflectors that essentially reflect back to different pins of the rotors. Since the circuit is unique, if we can figure out what "W" was mapped to (say "X"), then "X" would be mapped to "W".

Alan Turing was able to build the Bombe, a large electromagnetic device whose job, as described by Gordon Welchman, was simply to "bring 'further analysis' to a manageable number".

### AES and Key Exchanges

Now that the idea of substitution ciphers was clear, we wanted to explain the process of establishing the key. AES or other symmetric ciphers require that the sender encrypts the message using a key and the recipient decrypts it using the same (or a different) key. The answer lies in modular arithmetic again!

{{ img(id="image3.jpeg", alt="Alt Text", class="textCenter") }}

#### Diffie-Hellman Exchange

We talked about the basics of the Diffie-Hellman key exchange protocol, which is a method of digital encryption that allows two parties to send their keys over a public channel without fearing any adversary.

It works thanks to the magic of modular arithmetic.

### Conclusion

The collaborative session by the Cybersecurity and Maths Clubs for the freshers of 2024 was a resounding success. This event showcased the Cybersecurity Club's dedication to making complex topics accessible and engaging. The session left a lasting impression, igniting a passion for hacking and cracking in all who participated.

{{ img(id="image4.jpeg", alt="Alt Text", class="textCenter") }}
