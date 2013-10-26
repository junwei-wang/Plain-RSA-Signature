#include <NTL/ZZ.h>

/*
 * Name: Junwei Wang
 * Date: 16th, Oct, 2013
 */

using namespace NTL;

/*
 * Generate RAS keys "pub_key[2]" and "prv_key[3]" with "length" size of N.
 */
void keygen(unsigned int length, ZZ pub_key[], ZZ prv_key[], const ZZ & seeds);

/*
 * Sign "message" using "prv_key[3]", storing in "signature",
 *    if error happens in the sign process, signature = -1.
 */
void sign(ZZ & signature, const ZZ pub_key[], const ZZ prv_key[], const ZZ & message);

/*
 * Verify "signature " of "message" using "pub_key[2]".
 */
int verify(const ZZ pub_key[], const ZZ & message, const ZZ & signature);
