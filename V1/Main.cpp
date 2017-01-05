#include <iostream>
#include "rsa.h"
#include "hex.h"
#include "files.h"
#include "modes.h"
#include "randpool.h"


#include <windows.h>
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

namespace { OFB_Mode<AES>::Encryption s_globalRNG; }
RandomNumberGenerator & GlobalRNG()
{
	return dynamic_cast<RandomNumberGenerator&>(s_globalRNG);
}

string RSASignFile(const char *privFilename, const char *messageFilename, const char *signatureFilename, RandomPool& randPool)
{
	string result;
	string ss = messageFilename;
	FileSource privFile(privFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA>::Signer priv(privFile);
	StringSource(ss, true, new SignerFilter(randPool, priv, new HexEncoder(new StringSink(result))));
	return result;

}

bool RSAVerifyFile(const char *pubFilename, const char *messageFilename, const char *signatureFlag, RandomPool& randPool)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSASS<PKCS1v15, SHA>::Verifier pub(pubFile);

	StringSource signatureFile(signatureFlag, true, new HexDecoder);
	if (signatureFile.MaxRetrievable() != pub.SignatureLength())
		return false;
	SecByteBlock signature(pub.SignatureLength());
	signatureFile.Get(signature, signature.size());

	VerifierFilter *verifierFilter = new VerifierFilter(pub);
	verifierFilter->Put(signature, pub.SignatureLength());
	StringSource f(messageFilename, true, verifierFilter);

	return verifierFilter->GetLastResult();
}

int main()
{
	RandomPool randPool;
	const char* seed = "illidan.org";
	randPool.Put((byte *)seed, strlen(seed));

	RandomPool randPool1;
	const char* seed1 = "illidan.org111";
	randPool1.Put((byte *)seed1, strlen(seed1));

	GenerateRSAKey(2048, "PrivateKey.key", "PublicKey.key", randPool);

	string c = RSAEncryptString("PublicKey.key", "你好啊啊  哈哈哈！", randPool);
	string m = RSADecryptString("PrivateKey.key", c.c_str(), randPool);
	
	string c1 = RSASignFile("PrivateKey.key", "你好啊！adfqasd", "", randPool);
	bool r = RSAVerifyFile("PublicKey.key", "你好啊！adfqasd", c1.c_str(), randPool1);

	return 0;
}