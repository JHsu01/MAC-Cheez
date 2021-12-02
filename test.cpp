#include <hashlibpp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
//#include <netdb.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <stdbool.h>
#include <assert.h>

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
	if (rsa == NULL) {
		printf("failed to read public key\n");
		exit(-1);
	}
	return rsa;
}

RSA* wrap_priv(char* key) {
	BIO* priv = BIO_new_mem_buf(key, -1);
	RSA* rsa = NULL;
	rsa = PEM_read_bio_RSAPrivateKey(priv, &rsa, NULL, NULL);
	if (rsa == NULL) {
		printf("failed to read private key\n");
		exit(-1);
	}
	return rsa;
}

void write_to_file(char* to_write, int len, char* file_path) {
	FILE* file = fopen(file_path, "w+"); //yeet any existing file lmao
	if (file == NULL) {
		printf("error opening file %s to write\n", file_path);
		exit(-1);
	}
	int ret = fwrite(to_write, 1, len, file);
	if (ret != len) {
		printf("error writing to file %s\n", file_path);
		fclose(file);
		exit(-1);
	}
}

char* malloc_and_read(char* file_name) {
        FILE* file = fopen(file_name, "r");
	if (file == NULL) {
		printf("failed opening file %s\n", file_name);
		exit(-1);
	}
        fseek(file, 0, SEEK_END);
        int file_size = ftell(file);
        fseek(file, 0, SEEK_SET);
        char* contents = (char*) malloc(file_size + 1);
        int ret = fread(contents, 1, file_size, file);
	if (ret != file_size) {
		printf("error reading from file %s\n", file_name);
		fclose(file);
		exit(-1);
	}
        contents[file_size] = 0;
        fclose(file);
	return contents;
}

char* mac_name;
char* pub_name;
char* priv_name;
char* cipher_name;

void generate_keys() {
	RSA* key_pair = RSA_generate_key(2048, 65537, NULL, NULL);
		//stack overflow says its the most popular exp lmao
	int key_size = RSA_size(key_pair);

	char* pub = malloc_and_extract_pub(key_pair);
	write_to_file(pub, strlen(pub), pub_name);
	free(pub);

	char* priv = malloc_and_extract_priv(key_pair);
	write_to_file(priv, strlen(priv), priv_name);
	free(priv);
}

void hash_enc(char* file_name, char* pub_file) {
	//printf("hash_enc start\n");
	hashwrapper* my_wrapper = new sha256wrapper();
	std::string hash = my_wrapper->getHashFromFile(file_name);
	write_to_file((char*) hash.c_str(), strlen(hash.c_str()), mac_name);

	char* pub = malloc_and_read(pub_file);
	RSA* rsa_pub = wrap_pub(pub);
	int key_size = RSA_size(rsa_pub);

	char* ciphertext = malloc_and_encrypt((char*) hash.c_str(), rsa_pub);
	write_to_file(ciphertext, key_size, cipher_name);
	free(ciphertext);
	free(pub);
}

void dec_verf(char* mac_file, char* ciphertext_file, char* priv_file) {
	//printf("dec_verf start\n");
	char* mac = malloc_and_read(mac_file);
	char* ciphertext = malloc_and_read(ciphertext_file);
	char* priv = malloc_and_read(priv_file);

	RSA* rsa_priv = wrap_priv(priv);
	int key_size = RSA_size(rsa_priv);

	char* plaintext = malloc_and_decrypt(ciphertext, rsa_priv);
	//printf("plaintext: %s\n", plaintext);
	if (strcmp(mac, plaintext) == 0) {
		printf("password files match\n");
		printf("hash: %s\n", mac);
	} else {
		printf("password files do not match*\n");
		printf("our hash:\t%s\n", mac);
		printf("their hash:\t%s\n", plaintext);
	}

	free(mac);
	free(ciphertext);
	free(priv);
	free(plaintext);
}

int main(int argc, char** argv) {
	//args structure
	//	./test name keys
	//		generate keys and save to pub, priv_D0_NOT_SEND
	//	./test name hash_enc file pub
	//		hashes file and encrypts with pub
	//		saves output to ciphertext
	//	./test name dec_verf mac ciphertext
	//		outputs to screen whether or not shit was good

	char* my_name = argv[1]; //for the purposes of differentiation
	char* func = argv[2];
	error = (char*) malloc(240);

	//setting names
	mac_name = "mac";
	pub_name = (char*) malloc(100);
	strcpy(pub_name, "pub_");
	strcat(pub_name, my_name);
		//printf("pub name: %s\n", pub_name);
	priv_name = (char*) malloc(100);
	strcpy(priv_name, "priv_");
	strcat(priv_name, my_name);
	strcat(priv_name, "_DO_NOT_SEND");
		//printf("priv_name: %s\n", priv_name);
	cipher_name = (char*) malloc(100);
	strcpy(cipher_name, "ciphertext_");
	strcat(cipher_name, my_name);
		//printf("cipher_name: %s\n", cipher_name);

	if (strcmp(func, "keys") == 0) {
		generate_keys();
	} else if (strcmp(func, "hash_enc") == 0) {
		char* file_name = argv[3];
		char* pub_file = argv[4];
		hash_enc(file_name, pub_file);
	} else if (strcmp(func, "dec_verf") == 0) {
		char* mac_file = argv[3];
		char* ciphertext_file = argv[4];
		char* priv_file = priv_name;
		dec_verf(mac_file, ciphertext_file, priv_file);
	} else {
		printf("invalid args lmao\n");
	}

}
