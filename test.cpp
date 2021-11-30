#include <hashlibpp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <string.h>

char* error;

char* malloc_and_encrypt(char* p, RSA* pub) {
	char* c = (char*) malloc(RSA_size(pub));
	int enc_ret = RSA_public_encrypt(strlen(p) + 1,
		(const unsigned char*) p, (unsigned char*) c,
		pub, RSA_PKCS1_OAEP_PADDING);
		//"highly recommended to use RSA_PKCS1_OAEP_PADDING
	if (enc_ret == -1) {
		printf("encrypt failed lmao\n");
		strcpy(c, "encryption failed lmao");
	}
	//printf("enc_ret: %d\n", enc_ret);
	return c;
}

char* malloc_and_decrypt(char* c, RSA* priv) {
	char* p = (char*) malloc(RSA_size(priv));
	int dec_ret = RSA_private_decrypt(RSA_size(priv),
		(const unsigned char*) c, (unsigned char*) p,
		priv, RSA_PKCS1_OAEP_PADDING);
		//because of padding, decryption size is key size
	if (dec_ret == -1) {
		printf("decryption failed lmao\n");
		//strcpy(p, "decryption failed lmao");

		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), error);
		printf("error: %s\n", error);
	}
	return p;
}

char* malloc_and_extract_pub(RSA* pair) {
	BIO* pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(pub, pair);
	size_t pub_len = BIO_pending(pub);
	char* key = (char*) malloc(pub_len + 1);
		//+ 1 for the null term
	BIO_read(pub, key, pub_len);
	key[pub_len] = 0; //null term
	return key;
}

char* malloc_and_extract_priv(RSA* pair) {
	BIO* priv = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(priv, pair, NULL, NULL, 0, NULL, NULL);
	size_t priv_len = BIO_pending(priv);
	char* key = (char*) malloc(priv_len + 1);
	BIO_read(priv, key, priv_len);
	key[priv_len] = 0;
	return key;
}

RSA* wrap_pub(char* key) {
	BIO* pub = BIO_new_mem_buf(key, -1);
	//printf("pub here\n");
	RSA* rsa = NULL;
	rsa = PEM_read_bio_RSAPublicKey(pub, &rsa, NULL, NULL);
	//may have to change to RSA_PUBKEY
	//printf("pub before ret\n");
	return rsa;
}

RSA* wrap_priv(char* key) {
	BIO* priv = BIO_new_mem_buf(key, -1);
	RSA* rsa = NULL;
	rsa = PEM_read_bio_RSAPrivateKey(priv, &rsa, NULL, NULL);
	return rsa;
}

int main() {
	hashwrapper* my_wrapper = new sha256wrapper();
	std::string hash = my_wrapper->getHashFromFile("bug.png");
	//printf("hash: %s\n", hash.c_str());

	//char* plain_text = "suck a cock lmao";
	char* plain_text = (char*) hash.c_str();
	//technically i could make the hash into a really large integer
	//but then i would have to also make slight mods to enc/dec
	//so that they work on plain memory spans
	//TODO: make it more efficient as above if there's time
	int msg_len = strlen(plain_text);
	error = (char*) malloc(240);

	//key generation
	RSA* key_pair = RSA_generate_key(2048, 65537, NULL, NULL);
		//stack overflow says its the most popular exp lmao
	int key_size = RSA_size(key_pair);
	printf("max msg length: %d\n", key_size);

	//key extraction
	char* pub = malloc_and_extract_pub(key_pair);
	char* priv = malloc_and_extract_priv(key_pair);

	//key regeneration
	RSA* rsa_pub = wrap_pub(pub);
	RSA* rsa_priv = wrap_priv(priv);

	//encryption
	char* cipher_text = malloc_and_encrypt(plain_text, rsa_pub);

	//decryption
	char* decrypted_plain = malloc_and_decrypt(cipher_text, rsa_priv);

	printf("decrypted_plain: %s\n", decrypted_plain);
	free(cipher_text);
	free(decrypted_plain);
	return 0;
}
