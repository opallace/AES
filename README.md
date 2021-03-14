# AES
Uma simples implementação da criptografia AES ECB na linguagem C com a utilização de padding PKCS7. 

# Exemplo


```sh
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "aes.h"
#include "aux.h"

int main(){
	FILE *plain_text = fopen("plain", "r+b");
	FILE *key        = fopen("key", "r+b");
	FILE *out_enc    = fopen("out.enc", "w+b");
	FILE *out_plain  = fopen("out.plain", "w+b");

	AES_Encrypt(plain_text, out_enc, key);
	AES_Decrypt(out_enc, out_plain, key);

	return 0;
}
```
