#include <iostream>
#include <math.h>

unsigned long ComputePrime(unsigned long minNumber, unsigned long maxNumber)
{
	if (minNumber > maxNumber)
		return 0;

	for (unsigned long i = minNumber; i <= maxNumber; ++i)
	{
		unsigned long k = (unsigned long)sqrtl(i);
		unsigned long j;
		for (j = 2; j <= k; ++j)
		{
			if (i % j == 0)
				break;
		}
		if (j > k)
		{
			return i;
		}
	}

	return 0;
}

unsigned long ComputeMod(unsigned long minNumber, unsigned long maxNumber, unsigned long e, unsigned long on)
{
	for (unsigned long i = minNumber; i <= maxNumber; ++ i)
	{
		if ((i * e - 1) % on == 0)
		{
			return i;
		}
	}

	return 0;
}

struct PublicKey
{
	unsigned long n;
	unsigned long e;
};

struct PrivateKey
{
	unsigned long n;
	unsigned long d;
};

unsigned long Encrypt(PublicKey pk, unsigned long n)
{
	unsigned long l = (unsigned long)powl(n, pk.e);
	return l % pk.n;
}

unsigned long Decrypt(PrivateKey sk, unsigned long c)
{
	unsigned long l = (unsigned long)powl(c, sk.d);
	return l % sk.n;
}
 
unsigned long Encrypt(PrivateKey sk, unsigned long n)
{
	unsigned long l = (unsigned long)powl(n, sk.d);
	return l % sk.n;
}

unsigned long Decrypt(PublicKey pk, unsigned long c)
{
	unsigned long l = (unsigned long)powl(c, pk.e);
	return l % pk.n;
}

//本实例只是研究RSA原理。
int main()
{
	//计算公匙和私匙
	unsigned long p = ComputePrime(3, 10);
	unsigned long q = ComputePrime(p + 1, 10);

	unsigned long n = p * q;
	unsigned long on = (p - 1) * (q - 1);

	unsigned long e = ComputePrime(11, 20);
	unsigned long d = ComputeMod(2, 100, e, on);

 	PublicKey pKey = { n, e };
	PrivateKey sKey = { n, d };

	//模拟加密解密过程
	unsigned long pm = 7;
	unsigned long sm = Encrypt(pKey, pm);
	unsigned long apm = Decrypt(sKey, sm);

	//模拟加密解密过程 - 反过来加密不成立。
	//unsigned long pm1 = 9;
	//unsigned long sm1 = Encrypt(sKey, pm1);
	//unsigned long apm1 = Decrypt(pKey, sm1);


	return 0;
}