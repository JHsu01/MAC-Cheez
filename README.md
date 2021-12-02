# Top Secret Project Name: MAC & Che-ez 

Team Lettuce (IN) 

# How to use:

Test.cpp has multiple functions critical to Alice and Bob's goals. It allows the user to encypt (using RSA) and decrypt inputs. It also allows for a file to be hashed by the SHA 256 Algorithm. In addition, it also generates a new public and private key if needed. The bash functions included in this resporitory are simply for sending documents over IP & port. 

In theory, bob and alice will both take their file, hash it, and encrypt the hash. They will then send the encrypted ciphertext it to each other's IP adress. The other party will then decrypt the ciphertext with their private key, then compare the hash generated. 

# Sample commands
<pre>
To generate new keys
  ./lettuce your_name_here keys
To hash and encrypt a file "file_to_encrypt" with the public key "pub_name"
  ./lettuce your_name_here hash_enc file_to_encrypt pub_name
To decrypt and verify a ciphertext "ciphertext_file" and compare with the MAC "mac"
  ./lettuce your_name_here dec_verf mac ciphertext_file
To receive a file "file_to_receive"
  ./receive "file_to_receive"
To send a file "file_to_send" to person at ip "ip_address_here"
  ./send file_to_send ip_address_here
</pre>

# Sample usage
<pre>
Assume that we are Alice and wants to see if bob's files matches ours
Wait for bob to send their ciphertext
  ./receive "ciphertext_bob"
In the mean time, hash, encrypt, and send ciphertext to bob in another terminal
  ./lettuce alice hash_enc password_file.txt pub_bob
  ./send ciphertext_alice bob_ip_address_here
Once we receive the ciphertext from bob, decrypt and verify it with our MAC
  ./lettuce alice dec_verf our_mac_file ciphertext_bob
</pre>

# Notes and whatever else
<pre>
We assume that alice and bob know's each other's public key, the generate keys function is there for either debugging or if they want to make new keys for some reason.
We also assume that alice and bob know's each other IP address (they gotta actually be able to send stuff to each other somehow).
  If that isn't a valid assumption (or if Alice and Bob can't operate the send/receeive scripts), then worst case scenario they can literally just send the necessary ciphertexts to each other in some authenticated communication channel of their choosing. The IP and port communication was chosen because it is the most generic and is an example of a non-secure channel (aka anyone can just snoop in and see the packets being sent).
Having Alice and Bob enter their names when running the various commands is simply for ease of use and so that they don't mix up each other's keys or ciphertexts. Technically if they so desire, there's nothing stopping them from entering the other's name, but that has no cryptographic advantage (you can't learn the other person's file) and only serves to hinder/confuse communication.
Alice and Bob may need to compile the program. The necessary libraries are hashlibpp and openssl.
Alice and Bob may need to "chmod +x send receive".
The send and receieve scripts are written in bash because we couldn't get broken_server.cpp to work. Apparently c/cpp socket programming is hell, and Gustavo never taught us how to make a client.
</pre>
