#include <iostream>
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "randpool.h"

using namespace std;
using namespace CryptoPP;


void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, RandomPool& randPool)//产生公钥密钥文件  
{
	//生成私匙
	RSAES_OAEP_SHA_Decryptor  priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);       
	privFile.MessageEnd();

	//生成公匙
	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.MessageEnd();
}

string RSAEncryptString(const char *pubFilename, const char *message, RandomPool& randPool)//加密  
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);

	string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}

string RSADecryptString(const char *privFilename, const char *ciphertext, RandomPool& randPool)//解密  
{
	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);

	string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(randPool, priv, new StringSink(result))));
	return result;
}

int main()
{
	RandomPool randPool;
	const char* seed = "illidan.org";
	randPool.Put((byte *)seed, strlen(seed));

	GenerateRSAKey(2048, "PrivateKey.key", "PublicKey.key", randPool);

	string c = RSAEncryptString("PublicKey.key", "你好啊啊  哈哈哈！", randPool);
	string m = RSADecryptString("PrivateKey.key", c.c_str(), randPool);

	return 0;
}