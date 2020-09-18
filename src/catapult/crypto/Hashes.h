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

#pragma once
#include "OpensslContexts.h"
#include "catapult/types.h"

namespace catapult { namespace crypto {

	// region free functions

	/// Calculates the ripemd160 hash of \a dataBuffer into \a hash.
	void Ripemd160(const RawBuffer& dataBuffer, Hash160& hash);

	/// Calculates the Bitcoin hash 160 of \a dataBuffer into \a hash (sha256 + ripemd).
	void Bitcoin160(const RawBuffer& dataBuffer, Hash160& hash);

	/// Calculates the double sha256 hash of \a dataBuffer into \a hash.
	void Sha256Double(const RawBuffer& dataBuffer, Hash256& hash);

	/// Calculates the sha256 hash of \a dataBuffer into \a hash.
	void Sha256(const RawBuffer& dataBuffer, Hash256& hash);

	/// Calculates the sha512 hash of \a dataBuffer into \a hash.
	void Sha512(const RawBuffer& dataBuffer, Hash512& hash);

	/// Calculates the 256-bit SHA3 hash of \a dataBuffer into \a hash.
	void Sha3_256(const RawBuffer& dataBuffer, Hash256& hash);

	/// Calculates the sha256 HMAC of \a input with \a key, producing \a output.
	void Hmac_Sha256(const RawBuffer& key, const RawBuffer& input, Hash256& output);

	// endregion

	// region hash builders

	/// Use with HashBuilderT to generate SHA2 hashes.
	struct Sha2ModeTag {};

	/// Use with HashBuilderT to generate SHA3 hashes.
	struct Sha3ModeTag {};

	/// Builder for building a keccak hash.
	template<typename TModeTag, typename THashTag, size_t Block_Size>
	class HashBuilderT {
	public:
		using OutputType = utils::ByteArray<THashTag>;
		static constexpr size_t Hash_Block_Size = Block_Size;

	public:
		/// Creates a builder.
		HashBuilderT();

	public:
		/// Updates the state of hash with data inside \a dataBuffer.
		void update(const RawBuffer& dataBuffer);

		/// Updates the state of hash with concatenated \a buffers.
		void update(std::initializer_list<const RawBuffer> buffers);

		/// Finalize hash calculation. Returns result in \a output.
		void final(OutputType& output);

	private:
		OpensslDigestContext m_context;
	};

	/// Sha256_Builder.
	using Sha256_Builder = HashBuilderT<Sha2ModeTag, Hash256_tag, 64>;
	extern template class HashBuilderT<Sha2ModeTag, Hash256_tag, 64>;

	/// Sha512_Builder.
	using Sha512_Builder = HashBuilderT<Sha2ModeTag, Hash512_tag, 128>;
	extern template class HashBuilderT<Sha2ModeTag, Hash512_tag, 128>;

	/// Sha3_256_Builder.
	using Sha3_256_Builder = HashBuilderT<Sha3ModeTag, Hash256_tag, 136>;
	extern template class HashBuilderT<Sha3ModeTag, Hash256_tag, 136>;

	/// GenerationHash_Builder.
	using GenerationHash_Builder = HashBuilderT<Sha3ModeTag, GenerationHash_tag, 72>;
	extern template class HashBuilderT<Sha3ModeTag, GenerationHash_tag, 72>;

	// endregion
}}
