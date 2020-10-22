#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
void printBN(char* msg, BIGNUM* a);
BIGNUM* Get_Rsa(BIGNUM* p, BIGNUM* q, BIGNUM* e);

int main()
{
	//TASK 1
	printf("---------------------------------------------------------\n");
    printf("Starting Task1\n");
    //making the variables initializing them
    BIGNUM *p = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "0D88C3");
    	
	BIGNUM* key = Get_Rsa(p, q, e);
	printBN("p: ", p);
	printBN("q: ", q);
	printBN("e: ", e);
	printBN("Private key: ", key);
	printf("\n");
	
	// Task 2 
	printf("---------------------------------------------------------\n");
	printf("Doing Task 2\n");	
	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();

	//all the given keys needed initialized
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	BIGNUM* public = BN_new();
	BN_hex2bn(&public, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BIGNUM* private = BN_new();
	BN_hex2bn(&private, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	printBN("Public key: ", public);
	printf("\n");
	
	
	BIGNUM* plaintext = BN_new();
	BN_hex2bn(&plaintext, "4120746f702073656372657421");
	printBN("plaintext Hex:", plaintext);

	//encrypting
	BN_CTX *ctx1 = BN_CTX_new();
	BIGNUM* enc1 = BN_new();
	BN_mod_exp(enc1, plaintext, mod, public, ctx1);
	BN_CTX_free(ctx1);
	printBN("Encrypted plaintext:", enc1);

	//decrypting to make sure it was right
	BN_CTX *ctx2 = BN_CTX_new();
	BIGNUM* dec1 = BN_new();
	BN_mod_exp(dec1, enc1, private, public, ctx2);
	BN_CTX_free(ctx2);
	printBN("decrypted message:", dec1);

	// Task 3
	printf("---------------------------------------------------------\n");
	printf("Doing Task 3\n");
	//since all the public and private keys are the same we just have to decrypt the text and then use python to make it ascii
	BIGNUM* encrypted = BN_new();
	BN_hex2bn(&encrypted, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

	BN_CTX *ctx3 = BN_CTX_new();
	BIGNUM* dec2 = BN_new();
	BN_mod_exp(dec2, encrypted, private, public, ctx3);
	BN_CTX_free(ctx3);
	printBN("decrypted message:", dec2);

	// Task 4
	printf("---------------------------------------------------------\n");
	printf("Doing Task 4\n");
   
}
BIGNUM* Get_Rsa(BIGNUM* p, BIGNUM* q, BIGNUM* e){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* p_minus_one = BN_new();
	BIGNUM* q_minus_one = BN_new();
	BIGNUM* one = BN_new();
	BIGNUM* tt = BN_new();

	BN_dec2bn(&one, "1");
	BN_sub(p_minus_one, p, one);
	BN_sub(q_minus_one, q, one);
	BN_mul(tt, p_minus_one, q_minus_one, ctx);

	BIGNUM* res = BN_new();
	BN_mod_inverse(res, e, tt, ctx);
	BN_CTX_free(ctx);
	return res;
}
void printBN(char* msg, BIGNUM * a){
    char * number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}
    
