#include "plain_RSA_signature.h"
#include <time.h>

/*
 * Name: Junwei Wang
 * Date: 23rd, Oct, 2013
 */

void keygen(unsigned int length, ZZ pub_key[], ZZ prv_key[], const ZZ & seeds)
{
	int err = 80;
	ZZ p, q, N, phi_N, e, d;
	SetSeed(seeds);

	while (true) {
		while (true) {
			GenPrime(p, length / 2, err);
			GenPrime(q, length / 2, err);

			N = p * q;
			phi_N = (p - 1) * (q - 1);

			e = RandomBnd(N);	
			if (GCD(e, phi_N) == 1)
				break;
		}

		ZZ inv_phi_N, gcd;
		XGCD(gcd, d, inv_phi_N, e, phi_N);
		
		if (d > 0)
			break;
	}
	
	pub_key[0] = N;
	pub_key[1] = e;
	prv_key[0] = p;
	prv_key[1] = q;
	prv_key[2] = d;
}

void sign(ZZ & signature, const ZZ pub_key[], const ZZ prv_key[], const ZZ & message)
{
	ZZ p = prv_key[0], q = prv_key[1], d = prv_key[2];
        ZZ m_p, m_q; 
	ZZ inv_q, sub;

	long changed;

	m_p = PowerMod(message, d, p);
	m_q = PowerMod(message, d, q);

	/* use Chinese Reminder Theorem (CRT) in library */
//	changed = CRT(m_p, p, m_q, q);
//	if (changed) {
//		signature = m_p;
//		if (signature < 0) 
//			signature += p;
//	}

	/* impelmentation CRT by myself */
	sub = m_p - m_q;
	inv_q = InvMod(q % p, p);
	if (sub < 0)
		signature = m_q + q * inv_q * sub;
	else 	
		signature = m_q + q * inv_q * (sub + p);
	signature %= p * q;

	if (!verify(pub_key, message, signature))
		signature = -1;
}

int verify(const ZZ pub_key[], const ZZ & message, const ZZ & signature)
{
	if (message == PowerMod(signature, pub_key[1], pub_key[0]))
		return 1;

	return 0;
}
