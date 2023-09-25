#include <hashlibpp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>

char* hash_string;
char* pub_key;
char* priv_key;
int key_length; //pub and priv keys are supposed to be the same length

char* error;

char* client_ip;
int server_port;
int client_port;

char* their_pub_key;

//pthread_mutex_t their_key_mut;
bool got_their_key;
//pthread_cond_t their_key_cond;
//pthread_mutex_t server_mut;
//pthread_mutex_t client_mut;

char* malloc_and_encrypt(char* p, RSA* pub) {
	char* c = (char*) malloc(RSA_size(pub));
	int enc_ret = RSA_public_encrypt(strlen(p) + 1,
		(const unsigned char*) p, (unsigned char*) c,
		pub, RSA_PKCS1_OAEP_PADDING);
		//"highly recommended to use RSA_PKCS1_OAEP_PADDING
	if (enc_ret == -1) {
		printf("encrypt failed\n");
		strcpy(c, "encryption failed");
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
		printf("decryption failed\n");
		//strcpy(p, "decryption failed");

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

int process_and_close_request(int fd) {
	printf("process_and_close_request\n");
	//write this later after you finish writing the client
	//read their public key
	their_pub_key = (char*) malloc(key_length);
	//pthread_mutex_lock(&their_key_mut);
	read(fd, their_pub_key, key_length);
	got_their_key = true;
	//pthread_mutex_unlock(&their_key_mut);
	//mutex signal for their public key
	//pthread_mutex_lock(&their_key_mut);
	//pthread_cond_signal(&their_key_cond);
	//pthread_mutex_unlock(&their_key_mut);
	//read their encrypted hash
	char their_encrypted_hash[key_length];
	read(fd, their_encrypted_hash, key_length);
	//decrypting their hash
	RSA* our_rsa_priv = wrap_priv(priv_key);
	char* decrypted_hash = malloc_and_decrypt(their_encrypted_hash,
				our_rsa_priv);
	if (strcmp(hash_string, decrypted_hash) == 0) {
		//strings match
		printf("decrypted hash matches our hash\n");
		printf("our password files are the same\n");
	} else {
		printf("decrypted hash does not match our hash\n");
		printf("our password files are not the same*\n");
	}
	//mutex signal ending server
	//pthread_mutex_unlock(&server_mut);
	//free local mallocs
	free(decrypted_hash);
	close(fd);
	printf("process_and_close_request end\n");
}

void server() {
	printf("server\n");
	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
		//could further limit to just B's addr
		//like as a pass in arg
	server_addr.sin_port = htons(server_port);
	printf("server here 0\n");
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	printf("server_here 1\n");
	printf("server socket: %d\n", server_socket);
	if (server_socket < 0) {
		printf("error making socket\n");
		return;
	}
	//enable reuse port, literally just copying gustavo at this point
	int optval = 1;
	setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
		(char *) &optval, sizeof(int));
	int bind_ret = bind(server_socket, (struct sockaddr*) &server_addr,
			sizeof(server_addr));
	if (bind_ret) {
		printf("error binding socket\n");
		return;
	}
	//put sock in listening mode
	int listen_ret = listen(server_socket, 10);
		//allow 10 queued connection, still easily ddosed tho
		//cause the connections are queued and i cant be bothered
		//to actually implement multiple verifiers
	if (listen_ret) {
		printf("error listening\n");
		return;
	}

	printf("server here 2\n");
	//accept incoming connections
	//while (1)
		struct sockaddr_in client_addr;
		int alen = sizeof(client_addr);
		printf("server here 2 before accept\n");
		int client_socket = accept(server_socket,
					(struct sockaddr *) &client_addr,
					(socklen_t*) &alen);
		printf("server here 3 after accept\n");
		printf("client socket: %d\n", client_socket);
		if (client_socket < 0) {
			printf("error accepting\n");
			//continue;
			return;
		}

		//int i = process_request(client_socket);
		//if (i == 1) {	//files are the same
		//	close(client_socket);
		//	return;	//no reason to keep server open anymore
		//}
		//close(client_socket);

		printf("server here 3\n");

		process_and_close_request(client_socket);
		//TODO: add pthread create resume above
		//so you can process multiple requests at a time
		//just in case the adv tries to ddos
	//}
		printf("server end\n");
}

void send_request(int fd) {
	printf("send_request\n");
	//send them my pub key
	write(fd, pub_key, key_length);
	printf("send_request pub key sent\n");
	//mutex wait for their public key
	//pthread_mutex_lock(&their_key_mut);
	//lmao lets just do semi-busy waiting
	while(!got_their_key) {
		usleep(100000);
	}
	printf("send_request got their key\n");
	//encrypt message with their public key
	RSA* their_rsa_pub = wrap_pub(their_pub_key);
	char* encrypted_hash = malloc_and_encrypt(hash_string, their_rsa_pub);
	//send them my ciphertext
	write(fd, encrypted_hash, key_length);
	printf("send_request ciphertext sent");
	//mutex signal ending client
	//pthread_mutex_unlock(&client_mut);
	//freeing local mallocs
	free(encrypted_hash);
	printf("send_request end\n");
}

void client() {
	printf("client\n");
	struct sockaddr_in server_addr;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(client_port);
		//port client will use to send stuff, aka other server's port
	inet_pton(AF_INET, client_ip, &(server_addr.sin_addr));
	connect(sockfd, (struct sockaddr*) &server_addr,
		sizeof(server_addr.sin_addr));
	send_request(sockfd);
	printf("client end\n");
}

int main(int argc, char** argv) {
//	hashwrapper* my_wrapper = new sha256wrapper();
//	std::string hash = my_wrapper->getHashFromFile("bug.png");
//	//printf("hash: %s\n", hash.c_str());
//
//	//char* plain_text = "test plaintext message";
//	char* plain_text = (char*) hash.c_str();
//	//technically i could make the hash into a really large integer
//	//but then i would have to also make slight mods to enc/dec
//	//so that they work on plain memory spans
//	//TODO: make it more efficient as above if there's time
//	int msg_len = strlen(plain_text);
//	error = (char*) malloc(240);
//
//	//key generation
//	RSA* key_pair = RSA_generate_key(2048, 65537, NULL, NULL);
//	int key_size = RSA_size(key_pair);
//	printf("max msg length: %d\n", key_size);
//
//	//key extraction
//	char* pub = malloc_and_extract_pub(key_pair);
//	char* priv = malloc_and_extract_priv(key_pair);
//
//	//key regeneration
//	RSA* rsa_pub = wrap_pub(pub);
//	RSA* rsa_priv = wrap_priv(priv);
//
//	//encryption
//	char* cipher_text = malloc_and_encrypt(plain_text, rsa_pub);
//
//	//decryption
//	char* decrypted_plain = malloc_and_decrypt(cipher_text, rsa_priv);
//
//	printf("decrypted_plain: %s\n", decrypted_plain);
//	free(cipher_text);
//	free(decrypted_plain);
//	return 0;

	//reading program args
	//char* file_name = argv[1];
	//client_ip = argv[2];
	//char* name = argv[3];

	//ex testing, remember to remove
	char* file_name = "bug.png";
	client_ip = "localhost";
	char* name = "C"; //local testing

	//setting port numbers
	if (strcmp(name, "A") == 0) {
		server_port = 42069;
		client_port = 42070;
	} else if (strcmp(name, "B") == 0) {
		server_port = 42070;
		client_port = 42069;
	} else { //local test
		server_port = 42071;
		client_port = 42071;
	}

	//generating the hash
	hashwrapper* my_wrapper = new sha256wrapper();
	std::string hash = my_wrapper->getHashFromFile(file_name);
	hash_string = (char*) hash.c_str();

	//generating our keys
	RSA* key_pair = RSA_generate_key(2048, 65537, NULL, NULL);
	key_length = RSA_size(key_pair);
	pub_key = malloc_and_extract_pub(key_pair);
	priv_key = malloc_and_extract_priv(key_pair);

	//initing the mutexes
	//pthread_mutex_init(&their_key_mut, NULL);
	got_their_key = false;
	//pthread_mutex_init(&server_mut, NULL);
	//pthread_mutex_init(&client_mut, NULL);

	printf("creating server and clients\n");

	pthread_t server_thread;
	pthread_t client_thread;
	pthread_create(&server_thread, NULL, (void* (*)(void*)) &server, NULL);
	pthread_create(&client_thread, NULL, (void* (*)(void*)) &client, NULL);

	//waiting for threads to finish
	//pthread_mutex_lock(&server_mut);
	//pthread_mutex_lock(&client_mut);
	pthread_join(server_thread, NULL);
	pthread_join(client_thread, NULL);

	printf("main here\n");

	//freeing stuff
	free(pub_key);
	free(priv_key);
	free(their_pub_key);

	printf("main end\n");

	return 0;
}
