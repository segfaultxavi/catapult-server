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

#include "catapult/crypto_voting/VotingSigner.h"
#include "catapult/utils/RandomGenerator.h"
#include "tests/test/crypto/CurveUtils.h"
#include "tests/test/crypto/SignVerifyTests.h"
#include "tests/TestHarness.h"
#include <numeric>

namespace catapult { namespace crypto {

#define TEST_CLASS VotingSignerTests

	// region basic sign verify tests

	namespace {
		struct SignVerifyTraits {
		public:
			using KeyPair = crypto::VotingKeyPair;
			using Signature = crypto::VotingSignature;

		public:
			static crypto::VotingKeyPair GenerateKeyPair() {
				utils::LowEntropyRandomGenerator generator;
				return VotingKeyPair::FromPrivate(crypto::GenerateVotingPrivateKey(generator));
			}

			static auto GetPayloadForNonCanonicalSignatureTest() {
				// the value 30 in the payload ensures that the encodedS part of the signature is < 2 ^ 253 after adding the group order
				return std::array<uint8_t, 10>{ { 1, 2, 3, 4, 5, 6, 7, 8, 9, 30 } };
			}

			static auto MakeNonCanonical(const Signature& canonicalSignature) {
				// this is signature with group order added to 'encodedS' part of signature
				auto ed25519NonCanonicalSignature = canonicalSignature.copyTo<catapult::Signature>();
				test::ScalarAddGroupOrder(ed25519NonCanonicalSignature.data() + catapult::Signature::Size / 2);

				// preserve custom signature padding
				auto nonCanonicalSignature = ed25519NonCanonicalSignature.copyTo<Signature>();
				std::memcpy(
						nonCanonicalSignature.data() + catapult::Signature::Size,
						canonicalSignature.data() + catapult::Signature::Size,
						Signature::Size - catapult::Signature::Size);
				return nonCanonicalSignature;
			}
		};
	}

	DEFINE_SIGN_VERIFY_TESTS(SignVerifyTraits)

	// endregion

	// region test vectors

#define SIGNATURE_16_BYTE_PADDING "CACACACACACACACACACACACACACACACA"
#define SIGNATURE_PADDING SIGNATURE_16_BYTE_PADDING SIGNATURE_16_BYTE_PADDING

	namespace {
		struct TestVectorsInput {
			std::vector<std::string> InputData;
			std::vector<std::string> PrivateKeys;
			std::vector<std::string> ExpectedPublicKeys;
			std::vector<std::string> ExpectedSignatures;
		};

		// test vectors from rfc8032
		TestVectorsInput GetTestVectorsInput() {
			TestVectorsInput input;
			input.InputData = {
				"",
				"616263",
				"61626364656630313233343536373839",

				// long 133-byte msg, "q128_" followed by 128 'q'
				"713132385f717171717171717171717171717171717171717171717171717171"
				"7171717171717171717171717171717171717171717171717171717171717171"
				"7171717171717171717171717171717171717171717171717171717171717171"
				"7171717171717171717171717171717171717171717171717171717171717171"
				"7171717171",
				// "a512_" followed by 512 'a'
				"613531325f616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161616161616161616161616161616161616161616161616161616161"
				"6161616161"
			};

			input.PrivateKeys = {
				"9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60",
				"4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB",
				"C5AA8DF43F9F837BEDB7442F31DCB7B166D38535076F094B85CE3A2E0B4458F7",
				"F5E5767CF153319517630F226876B86C8160CC583BC013744C6BF255F5CC0EE5",
				"833FE62409237B9D62EC77587520911E9A759CEC1D19755B7DA901B96DCA3D42"
			};
			input.ExpectedPublicKeys = {
				"83F42AA882AA9BAD19C9BB34D30EA1D8D7D115E98F12D5773A0997B97C9B0D10C36568FF671A10F84FE446168E91B240",
				"984B31D42A256EC3D3783F8472D7CB0D96FD5619A0DAB19E30CEFFC66B906B270D041E8A944822F9F51A9DFA280BC244",
				"8FA114615C0D6D4ABC4FC86934B7B92D19FDB38B7CAAB0E59329B15B0139F972BCC730779D020BFABB3B8B71E50F3A1D",
				"19FFD4DC309425409ABEC7D86D02958D39973AC22A70EFA9379C26907863DD929DC3DC4174B55EBCE36218474DEE746E",
				"8B4CC87D0F7545F78235E1A5AA887D36E373146085FB87E6CA66301E5992C0BF8C295E4EE496026C0634F5ECFB9899F9"
			};

			// TODO: deliberately unfixed
			input.ExpectedSignatures = {
				"E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155"
				"5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B" SIGNATURE_PADDING,
				"92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA"
				"085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00" SIGNATURE_PADDING,
				"6291D657DEEC24024827E69C3ABE01A30CE548A284743A445E3680D7DB5AC3AC"
				"18FF9B538D16F290AE67F760984DC6594A7C15E9716ED28DC027BECEEA1EC40A" SIGNATURE_PADDING,
				"0AAB4C900501B3E24D7CDF4663326A3A87DF5E4843B2CBDB67CBF6E460FEC350"
				"AA5371B1508F9F4528ECEA23C436D94B5E8FCD4F681E30A6AC00A9704A188A03" SIGNATURE_PADDING,
				"DC2A4459E7369633A52B1BF277839A00201009A3EFBF3ECB69BEA2186C26B589"
				"09351FC9AC90B3ECFDFBC7C66431E0303DCA179C138AC17AD9BEF1177331A704" SIGNATURE_PADDING
			};

			// Sanity:
			EXPECT_EQ(input.InputData.size(), input.PrivateKeys.size());
			EXPECT_EQ(input.InputData.size(), input.ExpectedPublicKeys.size());
			EXPECT_EQ(input.InputData.size(), input.ExpectedSignatures.size());
			return input;
		}

		template<typename TArray>
		VotingSignature SignPayload(const VotingKeyPair& keyPair, const TArray& payload) {
			VotingSignature signature;
			EXPECT_NO_THROW(Sign(keyPair, payload, signature));
			return signature;
		}
	}

	TEST(TEST_CLASS, SignPassesTestVectors) {
		// Arrange:
		auto input = GetTestVectorsInput();

		// Act / Assert:
		for (auto i = 0u; i < input.InputData.size(); ++i) {
			// Act:
			auto keyPair = VotingKeyPair::FromString(input.PrivateKeys[i]);
			auto signature = SignPayload(keyPair, test::HexStringToVector(input.InputData[i]));

			// Assert:
			auto message = "test vector at " + std::to_string(i);
			EXPECT_EQ(utils::ParseByteArray<VotingKey>(input.ExpectedPublicKeys[i]), keyPair.publicKey()) << message;
			EXPECT_EQ(utils::ParseByteArray<VotingSignature>(input.ExpectedSignatures[i]), signature) << message;
		}
	}

	TEST(TEST_CLASS, VerifyPassesTestVectors) {
		// Arrange:
		auto input = GetTestVectorsInput();

		// Act / Assert:
		for (auto i = 0u; i < input.InputData.size(); ++i) {
			// Act:
			auto keyPair = VotingKeyPair::FromString(input.PrivateKeys[i]);
			auto payload = test::HexStringToVector(input.InputData[i]);
			auto signature = SignPayload(keyPair, payload);
			auto isVerified = Verify(keyPair.publicKey(), payload, signature);

			// Assert:
			auto message = "test vector at " + std::to_string(i);
			EXPECT_TRUE(isVerified) << message;
		}
	}

	// endregion
}}
