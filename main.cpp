
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include "debug.h"
#include <unistd.h>

unsigned int microseconds = 2000000;

#define port 1100
#define name 10

std::string text2 = "secondpass";
std::string text4 = "thirdpass ";

struct Keys {
  BIO* public_key;
  BIO* private_key;
};

std::string gettime ()
{
  time_t rawtime;
  struct tm * timeinfo;
  char buffer[80];

  time (&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(buffer,sizeof(buffer),"%D %T",timeinfo);
  std::string str(buffer);

  return str;
}

std::string comparetime(std::string time, std::string cur_time) {
	
}


std::string create_checking_certificate(RSA* private_key, RSA* public_key) {
	OpenSSL_add_all_digests();
	EVP_PKEY* publickey;
	publickey = EVP_PKEY_new();
	EVP_PKEY* privatekey;
	privatekey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(privatekey, private_key);
	EVP_PKEY_assign_RSA(publickey, public_key);
	X509 * x509;
	x509 = X509_new();
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
	X509_set_pubkey(x509, publickey);
	
	X509_NAME* n;
	n = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_txt(n, "C",  MBSTRING_ASC,
                           (unsigned char *)"CA", -1, -1, 0);
	X509_NAME_add_entry_by_txt(n, "O",  MBSTRING_ASC,
                           (unsigned char *)"MyCompany Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                           (unsigned char *)"localhost", -1, -1, 0);
	
	X509_set_issuer_name(x509, n);
	X509_sign(x509, privatekey, EVP_sha384());
	FILE * f;
	f = fopen("cert.pem", "rwb");
	PEM_write_X509(
		f,
		x509
	);
	std::ifstream ifs("cert.pem");
  std::string content( (std::istreambuf_iterator<char>(ifs) ),
                       (std::istreambuf_iterator<char>()    ) );
	return content;
}

int verify_cert(RSA* public_key, const std::string& certificate) {
	OpenSSL_add_all_digests();
	BIO *b = BIO_new(BIO_s_mem());
	BIO_puts(b, certificate.c_str());
	X509 * x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	EVP_PKEY * pubkey;
	pubkey = EVP_PKEY_new();	
	EVP_PKEY_assign_RSA(pubkey, public_key);
	int result = X509_verify(x509, pubkey);
	return result;
}

RSA* key_generation(std::string whose, int counter) {
  Keys* keys = new Keys();
  RSA* rsa;
  BIO *bp_public = NULL, *bp_private = NULL;
  BIGNUM *bne = NULL;
  int bits = 2048;
  unsigned long e = RSA_F4;
  int ret;
  int keylen;
  char *pem_key;

  bne = BN_new();
  ret = BN_set_word(bne,e);
  if(ret != 1){ abort();}

  char * number_str = BN_bn2dec(bne);

  rsa = RSA_new();
  ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
  if (ret != 1){abort();}

  BIO *bio_public = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bio_public, rsa);//, NULL, NULL, 0, NULL, NULL);
  keylen = BIO_pending(bio_public);
  pem_key = (char*)calloc(keylen+1, 1);
  BIO_read(bio_public, pem_key, keylen);
  std::ofstream out("/home/skotti/share/public_"+whose+"_"+std::to_string(counter)+".pem");
  out<<pem_key;

  BIO *bio_private = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(bio_private, rsa, NULL, NULL, 0, NULL, NULL);
  keylen = BIO_pending(bio_private);
  pem_key = (char*)calloc(keylen+1, 1);
  BIO_read(bio_private, pem_key, keylen);
  std::ofstream out1("/home/skotti/share/private_"+whose+"_"+std::to_string(counter)+".pem");
  out1<<pem_key;
  
  fflush(stdout);
	
	return rsa;
  }

RSA* read_private_key(int counter) {
	std::ifstream in("/home/skotti/share/private_server_"+std::to_string(counter)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

RSA* read_public_key(int counter) {
	std::ifstream in("/home/skotti/share/public_client_"+std::to_string(counter)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

RSA* read_own_public_key(int counter) {
	std::ifstream in("/home/skotti/share/public_server_"+std::to_string(counter)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
  return rsa;
}


bool RSASign( RSA* rsa, 
              const unsigned char* Msg, 
              size_t MsgLen,
              unsigned char** EncMsg, 
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create(); //- cоздает текущий контекст подписи
  EVP_PKEY* priKey  = EVP_PKEY_new(); //- аллоцирует память под новый приватный ключ
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha384(), NULL,priKey)<=0) {//- задает использование текущего контекста с таким то ключом
      return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {//- хэширует указанное число байт в текущий контекст
      return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {// - с NULL параметром получается достать максимальную длину для аллокации буфера
      return false;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);//-аллоцируем буфер
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {//- подписываем сообщение и кладем в буфер, в длину записывается реальное число байт
      return false;
  }
  EVP_MD_CTX_cleanup(m_RSASignCtx);
  return true;
}

bool RSAVerifySignature( RSA* rsa, 
                         unsigned char* MsgHash, 
                         size_t MsgHashLen, 
                         const char* Msg, 
                         size_t MsgLen, 
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();//-аллоцируется память для публичного ключа
  EVP_PKEY_assign_RSA(pubKey, rsa);//- в эту памть записывается публичный ключ
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create(); //- создается новый контекст для подписи

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha384(),NULL,pubKey)<=0) {//- инициируется верифицирующий контекст подписи
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
  }
}

void generate_random_number(std::string& random) {
	for (int i = 0; i < 10; i++)
		random.push_back((int)(49+rand()%9));
}

std::string generate_message_one_nosign(const std::string& random, const std::string& message/*, const std::string& b_name*//*, const std::string& time*/) {
  std::string text3("serverA    ");
	std::cout<<"Random number : "<<random<<std::endl;
	std::string result = random + message/* + b_name */+ "serverA   ";
	
	return result;
}

std::string generate_message_one_sign(const std::string& random, const std::string& message/*, const std::string& b_name*//*, const std::string& time*/) {
  std::string text3("serverA    ");
	std::string result = random + message/* + b_name*/ + "serverA   ";
	
	return result;
}

void copy_value(unsigned char* m, int length, std::string& s) {
		for (int i = 0; i < length; i++)
			s.push_back(m[i]);
}


int EVP_PKEY_get_type(EVP_PKEY *pkey)
{
    ASSERT(pkey);
    if (!pkey)
        return NID_undef;

    return EVP_PKEY_type(pkey->type);
}

bool isValidRSAPublicKeyOnly(RSA *rsa) {
    //from rsa_ameth.c do_rsa_print : has a private key
    //from rsa_chk.c RSA_check_key : doesn't have n (modulus) and e (public exponent)
    if (!rsa || rsa->d || !rsa->n || !rsa->e) {
        return false;
    }
    return BN_is_odd(rsa->e) && !BN_is_one(rsa->e);
}

bool isValidPublicKeyOnly(EVP_PKEY *pkey) {
    //EVP_PKEY_get_type from http://stackoverflow.com/a/29885771/2692914
    int type = EVP_PKEY_get_type(pkey); //checks nullptr
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_RSA2) {
        //not RSA
        return false;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        return false;
    }

    bool isValid = isValidRSAPublicKeyOnly(rsa);
    RSA_free(rsa);
    return isValid;
}


void process_connection(int socket, struct sockaddr_in& stSockAddr, std::string& received_message, RSA* private_key/*, RSA* public_key*/){
	char recv_buff[1000];
	memset(recv_buff, 0, 1000);
	stSockAddr.sin_family = AF_INET;
	stSockAddr.sin_port = htons(port);
	stSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	DASSERT(bind(socket, (struct sockaddr*) &stSockAddr, sizeof (stSockAddr)) != -1, "Ошибка связывания");
	DASSERT(listen(socket, 10) != -1, "Ошибка прослушивания");

	int i32ConnectFD;
	
	i32ConnectFD = accept(socket, 0, 0);

	DASSERT((i32ConnectFD > 0), "Ошибка принятия");
	std::cout<<"Client has connected"<<std::endl;
	//---------------------------------------------------------------------------------------------------------
	/****received client message****/
	usleep(microseconds);
	int read_bytes = read(i32ConnectFD, recv_buff, 200);
	DEBUG_ONLY(std::cout<<"Received bytes number : "<<read_bytes<<std::endl);
	usleep(microseconds);
	
	
	std::string nonceRB;
	std::string text_1;
	/****get data*****/
	for (int i = 0; i < (read_bytes - name); i++)
		nonceRB.push_back(recv_buff[i]);
	for (int i = (read_bytes - name); i < read_bytes; i++) {
			text_1.push_back(recv_buff[i]);
	}
	
	
	DEBUG_ONLY(std::cout<<"Received nonce :"<<nonceRB<<std::endl);
	usleep(microseconds);
	DEBUG_ONLY(std::cout<<"Received text_1 : "<<text_1<<std::endl);
	usleep(microseconds);
	
	
	std::string random;
	generate_random_number(random);
	std::string time_point_1 = gettime();
	std::string nonceRA = random;
	
	/*****generate signed and unsigned answer****/
	std::string server_answer_1 = generate_message_one_sign(random, nonceRB/*, B_name*//*, time_point_1*/);
	std::string server_answer_2 = generate_message_one_nosign(random, nonceRB/*, B_name*//*, time_point_1*/);
	
	/**sign message***/
	unsigned char* enc_msg;
	size_t enc_length;
	RSASign(private_key, (unsigned char*)server_answer_1.c_str(), server_answer_1.length(), &enc_msg, &enc_length);
	DEBUG_ONLY(std::cout<<"Encrypted message length : "<< enc_length<<std::endl);
	usleep(microseconds);
	
	/**debug print***/
	copy_value(enc_msg, enc_length, server_answer_2);
	std::ofstream out("test");
	DEBUG_ONLY(out<<"Server answer is : "<<server_answer_2<<std::endl);
	usleep(microseconds);
	
	/***send message**/
	int written_bytes = write(i32ConnectFD, server_answer_2.c_str(), server_answer_2.length());
	DEBUG_ONLY(std::cout<<"Sent bytes number : "<<written_bytes<<std::endl);
	usleep(microseconds);
	
	memset(recv_buff, 0, 1000);
	read_bytes = read(i32ConnectFD, recv_buff, 400);
	DEBUG_ONLY(std::cout<<"Received bytes number(second received message) : "<<read_bytes<<std::endl);
	usleep(microseconds);
	
	std::string received_nonceRA;
	std::string received_nonceRB;
	std::string received_B;
	
	
	//std::string received_time;
	int nonce_size = (read_bytes - 256 - 10)/2;
	for (int i = 0; i < nonce_size; i++)
		received_nonceRB.push_back(recv_buff[i]);
	for (int i = nonce_size; i < 2*nonce_size; i++)
		received_nonceRA.push_back(recv_buff[i]);
	for (int i = 2*nonce_size; i < 2*nonce_size + 10; i++)
		received_B.push_back(recv_buff[i]);

	DEBUG_ONLY(std::cout<<"Received A nonce : "<<received_nonceRA<<std::endl);
	usleep(microseconds);
	DEBUG_ONLY(std::cout<<"Received B nonce : "<<received_nonceRB<<std::endl);
	usleep(microseconds);
	DEBUG_ONLY(std::cout<<"Received B name : "<<received_B<<std::endl);
	usleep(microseconds);

	std::string encrypted_message;
	for (int i = (2*nonce_size + 10); i < read_bytes; i++)
		encrypted_message.push_back(recv_buff[i]);
	
	/******verification****/
	std::string message_to_verify = received_nonceRB + received_nonceRA + received_B/* + text4*/;
	
	std::cout<<received_B.substr(6, received_B.find(" ") - 6)<<std::endl;
	int clientNum = std::stoi(received_B.substr(6, received_B.find(" ") - 6));

	RSA* public_key = read_public_key(1);
	/*****ensure key posession***/
	EVP_PKEY* pubKey  = EVP_PKEY_new();//-аллоцируется память для публичного ключа
  EVP_PKEY_assign_RSA(pubKey, public_key);
	DASSERT(isValidPublicKeyOnly(pubKey), "SERVER IS IN POSESSION OF AN INVALID PUBLIC KEY");
	DEBUG_ONLY(std::cout<<"PUBLIC CLIENT KEY VERIFICATION HAS PASSED"<<std::endl);
	usleep(microseconds);
	/*****End********************/
	
	bool auth;
	int result = RSAVerifySignature(public_key, (unsigned char*)encrypted_message.c_str(), encrypted_message.length(), message_to_verify.c_str(), message_to_verify.length(), &auth);
	DASSERT(received_nonceRA == nonceRA, "NONCE RECEIVED VALUE AND SERVER VALUE ARE DIFFERENT");
	DASSERT(received_nonceRB == nonceRB, "NONCE RECEIVED VALUE IN THE FISRT AND IN THE LAST MESSAGE ARE DIFFERENT");
	DEBUG_ONLY(std::cout<<"RECEIVED NONCE IS EQUAL TO THE ORIGINAL"<<std::endl);
	DEBUG_ONLY(std::cout<<"RECEIVED NONCE IS EQUAL TO ONE, RECEIVED IN THE FIRST MESSAGE"<<std::endl);
	
	DEBUG_ONLY(std::cout<<"The result of comparision : "<<(result && auth)<<std::endl);
	if ((result&&auth) == 0)
	{
		std::cout<<"REGISTRATION FAILED"<<std::endl;
		abort();
	}
	usleep(microseconds);
	if(result&&auth) 
		std::cout<<"CLIENT IS REGISTERED"<<std::endl;
	
	//------------------------------------------------------------------------------------------------------------
}

void send_message_one() {
	
}

int main(void) {
	srand (time(NULL));
	struct sockaddr_in stSockAddr;
	int i32SocketFD = socket(AF_INET, SOCK_STREAM, 0);
	time_t ticks;
	std::string text("hey");
	int mode = 0;
	std::cout<<"Mode = 1 : key generation, mode = 0 : connection"<<std::endl;
	//std::cin>> mode;
	key_generation("server", 1);
	if (mode == 1) {
		
	key_generation("client", 1);
	
	} else {
	
	RSA* private_key = read_private_key(1);
//	RSA* public_key = read_public_key(1);
	RSA* own_public_key = read_own_public_key(1);
	fflush(stdout);
	unsigned char* encMessage;
	size_t encMessageLength;
	
 	std::string received_message;
 	process_connection(i32SocketFD, stSockAddr, received_message, private_key/*, (public_key*/);
	}
	return 0;
}