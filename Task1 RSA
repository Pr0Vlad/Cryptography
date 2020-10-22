#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

void printBN(char* msg, BIGNUM* a);
BIGNUM* Get_Rsa(BIGNUM* p, BIGNUM* q, BIGNUM* e);

int main()
{
    printf("Starting Task1\n");
    //making the variables initializing them
    BIGNUM *p = BN_new();
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "0D88C3");
    	
	BIGNUM* key = Get_Rsa(p, q, e);
	printBN("Private key: ", key);
	printf("\n");
	

   
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
    

