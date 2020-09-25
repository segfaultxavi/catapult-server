
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

#include "AggregateProofStorage.h"

namespace catapult { namespace io {

	namespace {
		class AggregateProofStorage : public ProofStorage {
		public:
			AggregateProofStorage(std::unique_ptr<ProofStorage>&& pStorage, subscribers::FinalizationSubscriber& subscriber)
					: m_pStorage(std::move(pStorage))
					, m_subscriber(subscriber)
			{}

		public:
			model::FinalizationStatistics statistics() const override {
				return m_pStorage->statistics();
			}

			std::shared_ptr<const model::FinalizationProof> loadProof(FinalizationEpoch epoch) const override {
				return m_pStorage->loadProof(epoch);
			}

			std::shared_ptr<const model::FinalizationProof> loadProof(Height height) const override {
				return m_pStorage->loadProof(height);
			}

			void saveProof(const model::FinalizationProof& proof) override {
				auto currentStatistics = statistics();
				if (currentStatistics.Round > proof.Round) {
					CATAPULT_LOG(debug)
							<< "skipping save of older proof with round " << proof.Round
							<< " when last saved proof is " << currentStatistics.Round;
					return;
				}

				CATAPULT_LOG(important)
						<< "<FIN> saving proof: round = " << proof.Round
						<< ", height = " << proof.Height
						<< ", hash = " << proof.Hash;

				m_pStorage->saveProof(proof);
				m_subscriber.notifyFinalizedBlock(proof.Round, proof.Height, proof.Hash);
			}

		private:
			std::unique_ptr<ProofStorage> m_pStorage;
			subscribers::FinalizationSubscriber& m_subscriber;
		};
	}

	std::unique_ptr<ProofStorage> CreateAggregateProofStorage(
			std::unique_ptr<ProofStorage>&& pStorage,
			subscribers::FinalizationSubscriber& subscriber) {
		return std::make_unique<AggregateProofStorage>(std::move(pStorage), subscriber);
	}
}}

