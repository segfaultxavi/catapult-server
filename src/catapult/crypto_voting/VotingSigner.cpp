/**
*** Copyright (c) 2016-present,
*** Jaguar0625, gimre, BloodyRookie, Tech Bureau, Corp. All rights reserved.
***
*** This file is part of Catapult.
***
*** Catapult is free software: you can redistribute it and/or modify
*** it under the terms of the GNU Lesser General Public License as published by
*** the Free Software Foundation, either version 3 of the License, or
*** (at your option) any later version.
***
*** Catapult is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*** GNU Lesser General Public License for more details.
***
*** You should have received a copy of the GNU Lesser General Public License
*** along with Catapult. If not, see <http://www.gnu.org/licenses/>.
**/

#include "VotingSigner.h"
#include "HashToCurve.h"
#include "catapult/crypto/Hashes.h"
#include "catapult/crypto/Signer.h"

#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
}

namespace catapult { namespace crypto {

	namespace {
		constexpr size_t Private_Key_Offset = BGS_BLS381 - VotingPrivateKey::Size;

		// region reduce/underduce helpers

		// G1
		bool ECP_BLS381_fromReducedG1(ECP_BLS381& p, const VotingKey& publicKey) {
			uint32_t prebit = (publicKey[0] & 0x80);
			BIG_384_58 px;

			char xCopy[MODBYTES_384_58];
			std::memcpy(xCopy, &(publicKey[0]), MODBYTES_384_58);
			xCopy[0] &= 0x7F;

			BIG_384_58_fromBytes(px, xCopy);

			if (ECP_BLS381_setx(&p, px, 0 == prebit ? 0 : 1))
				return true;

			return false;
		}

		// G2
		bool ECP2_BLS381_toReducedG2(VotingSignature& signature, const ECP2_BLS381& q) {
			BIG_384_58 temp;
			FP2_BLS381 qx, qy;
			if (-1 == ECP2_BLS381_get(&qx, &qy, const_cast<ECP2_BLS381*>(&q))) {
				// ERROR: point at INF;
				return false;
			}

			FP_BLS381_redc(temp, &(qx.a));
			BIG_384_58_toBytes(reinterpret_cast<char*>(&signature[0]), temp);
			FP_BLS381_redc(temp, &(qx.b));
			BIG_384_58_toBytes(reinterpret_cast<char*>(&signature[MODBYTES_384_58]), temp);

			// try to recover y from x
			// TODO: is there nicer way to mark, that y needs to be negated, when recovering during unreduce
			FP2_BLS381 recoveredY;
			ECP2_BLS381_rhs(&recoveredY, &qx);
			FP2_BLS381_sqrt(&recoveredY, &recoveredY);

			signature[0] = static_cast<uint8_t>(signature[0] | 0x80 * FP2_BLS381_equals(&qy, &recoveredY));
			return true;
		}

		bool ECP2_BLS381_fromReducedG2(ECP2_BLS381& q, const VotingSignature& signature) {
			uint32_t prebit = signature[0] & 0x80;

			char xCopy[MODBYTES_384_58];
			std::memcpy(xCopy, &(signature[0]), MODBYTES_384_58);
			xCopy[0] &= 0x7F;

			BIG_384_58 bx, by;
			BIG_384_58_fromBytes(bx, xCopy);
			BIG_384_58_fromBytes(by, const_cast<char*>(reinterpret_cast<const char*>(&(signature[MODBYTES_384_58]))));

			FP2_BLS381 qx;
			FP_BLS381_nres(&(qx.a), bx);
			FP_BLS381_nres(&(qx.b), by);

			// TODO: this will fail if (x,) is not on curve, that is fine, we'll use it to reject invalid sigs
			if (!ECP2_BLS381_setx(&q, &qx))
				return false;

			if (0 == prebit)
				ECP2_BLS381_neg(&q);

			return true;
		}

		// endregion
	}

	void Sign(const VotingKeyPair& keyPair, const RawBuffer& dataBuffer, VotingSignature& computedSignature) {
		Sign(keyPair, { dataBuffer }, computedSignature);
	}

	// variables follow naming in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.6
	void Sign(const VotingKeyPair& keyPair, std::initializer_list<const RawBuffer> buffersList, VotingSignature& computedSignature) {
		G2Point qr;
		HashToCurveG2(qr, buffersList);

		// copy private key to larger buffer
		std::array<char, BGS_BLS381> extendedPrivateKey{};
		std::memcpy(extendedPrivateKey.data() + Private_Key_Offset, keyPair.privateKey().data(), VotingPrivateKey::Size);

		BIG_384_58 sk;
		BIG_384_58_fromBytes(sk, extendedPrivateKey.data());
		PAIR_BLS381_G2mul(qr.get<ECP2_BLS381>(), sk);

		// TODO: qr should be proper point, so this will always succeed
		ECP2_BLS381_toReducedG2(computedSignature, qr.ref<ECP2_BLS381>());
	}

	bool Verify(const VotingKey& publicKey, const RawBuffer& dataBuffer, const VotingSignature& signature) {
		return Verify(publicKey, { dataBuffer }, signature);
	}

	// variables follow naming in
	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.7
	bool Verify(const VotingKey& publicKey, std::initializer_list<const RawBuffer> buffersList, const VotingSignature& signature) {
		ECP_BLS381 g;
		ECP_BLS381_generator(&g);

		ECP2_BLS381 r;
		if (!ECP2_BLS381_fromReducedG2(r, signature))
			return false;

		G2Point q;
		HashToCurveG2(q, buffersList);

		ECP_BLS381 xp;
		if (!ECP_BLS381_fromReducedG1(xp, publicKey))
			return false;

		// verify that: e(g1, sig) = e(pub, H(m))
		// this is equivalent to
		// (e(-g1, sig) * e(pub, H(m))^x = 1
		// so if result of exp is root of unity, verification succeeded
		//
		// note that:
		// e(-a, b) = e(a, b)^{-1} = e(a, -b)
		// so either g or sig could be negated, we're negating g
		ECP_BLS381_neg(&g);

		FP12_BLS381 v;
		PAIR_BLS381_double_ate(&v, &r, &g, q.get<ECP2_BLS381>(), &xp);
		PAIR_BLS381_fexp(&v);
		return !!FP12_BLS381_isunity(&v);
	}
}}
