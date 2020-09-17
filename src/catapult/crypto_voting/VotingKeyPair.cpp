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

#include "VotingKeyPair.h"
#include "catapult/crypto/SecureRandomGenerator.h"
#include "catapult/crypto/KeyPair.h"

#if defined(__clang__) || defined(__GNUC__)
#define C99
#endif

extern "C" {
#include <amcl/config_curve_BLS381.h>
#include <amcl/bls_BLS381.h>
#include <amcl/big_512_56.h>
#include <amcl/randapi.h>
}

namespace catapult { namespace crypto {

	namespace {
		constexpr size_t Private_Key_Offset = BGS_BLS381 - VotingPrivateKey::Size;

		// G1
		void ECP_BLS381_toReduced(VotingKey& g1Elem, const ECP_BLS381& point) {
			BIG_384_58 x, y;
			ECP_BLS381_get(x, y, const_cast<ECP_BLS381*>(&point));

			BIG_384_58_toBytes(reinterpret_cast<char*>(g1Elem.data()), x);
			g1Elem[0] = static_cast<uint8_t>(g1Elem[0] | 0x80 * BIG_384_58_parity(y));
		}
	}

	VotingPrivateKey GenerateVotingPrivateKey(const std::function<uint64_t()>& generator) {
		std::array<uint8_t, BGS_BLS381> privateKey;

		DBIG_384_58 randomData;
		BIG_384_58 secretKeyPoint;
		BIG_384_58 order;
		BIG_384_58_rcopy(order, CURVE_Order_BLS381);

		// note: this might be non-portable
		for (auto& chunk : randomData)
			chunk = static_cast<__int64_t>(generator() & 0x3FFFFFF'FFFFFFFF);

	    BIG_384_58_dmod(secretKeyPoint, randomData, order);
		BIG_384_58_toBytes(reinterpret_cast<char*>(privateKey.data()), secretKeyPoint);

		// TODO: wipe secretKeyPoint, wipe randomData, wipe randomData
		return VotingPrivateKey::FromBuffer({ privateKey.data() + Private_Key_Offset, VotingPrivateKey::Size });
	}

	void VotingKeyPairTraits::ExtractPublicKeyFromPrivateKey(const PrivateKey& privateKey, PublicKey& publicKey) {
		ECP_BLS381 g;
		ECP_BLS381_generator(&g);

		// copy private key to larger buffer
		std::array<char, BGS_BLS381> extendedPrivateKey{};
		std::memcpy(extendedPrivateKey.data() + Private_Key_Offset, privateKey.data(), VotingPrivateKey::Size);

		// multiply private key times group generator
		BIG_384_58 secretKeyPoint;
		BIG_384_58_fromBytes(secretKeyPoint, extendedPrivateKey.data());
		PAIR_BLS381_G1mul(&g, secretKeyPoint);

		// TODO: wipe secretKeyPoint, wipe g, wipe extendedPrivateKey
		ECP_BLS381_toReduced(publicKey, g);
	}
}}
