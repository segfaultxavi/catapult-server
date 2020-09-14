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

#include "finalization/src/FinalizationOrchestratorService.h"
#include "finalization/src/FinalizationBootstrapperService.h"
#include "finalization/src/FinalizationConfiguration.h"
#include "finalization/src/VotingStatusFile.h"
#include "finalization/src/chain/MultiRoundMessageAggregator.h"
#include "finalization/src/io/ProofStorageCache.h"
#include "catapult/config/CatapultDataDirectory.h"
#include "catapult/crypto_voting/AggregateBmPrivateKeyTree.h"
#include "catapult/io/FileStream.h"
#include "finalization/tests/test/FinalizationBootstrapperServiceTestUtils.h"
#include "finalization/tests/test/mocks/MockProofStorage.h"
#include "finalization/tests/test/mocks/MockRoundMessageAggregator.h"
#include "tests/test/local/ServiceLocatorTestContext.h"
#include "tests/test/local/ServiceTestUtils.h"
#include "tests/test/nodeps/Filesystem.h"
#include "tests/test/nodeps/TimeSupplier.h"
#include "tests/TestHarness.h"

namespace catapult { namespace finalization {

#define TEST_CLASS FinalizationOrchestratorServiceTests

	// region test context

	namespace {
		using VoterType = test::FinalizationBootstrapperServiceTestUtils::VoterType;

		constexpr auto Num_Dependent_Services = 3u;
		constexpr auto Default_Voting_Set_Grouping = 300u;
		constexpr auto Small_Voting_Set_Grouping = 49u;

		constexpr auto Finalization_Epoch = FinalizationEpoch(6);
		constexpr auto Prevote_Stage = model::FinalizationStage::Prevote;
		constexpr auto Precommit_Stage = model::FinalizationStage::Precommit;
		constexpr auto Default_Round = model::FinalizationRound{ Finalization_Epoch, FinalizationPoint(8) };

		struct FinalizationOrchestratorServiceTraits {
		public:
			static constexpr uint64_t Voting_Key_Dilution = 13;

		public:
			static auto CreateRegistrar(uint64_t votingSetGrouping) {
				// (Size, Threshold) are set in MockRoundMessageAggregator to (1000, 750)
				auto config = FinalizationConfiguration::Uninitialized();
				config.StepDuration = utils::TimeSpan::FromSeconds(10);
				config.MaxHashesPerPoint = 64;
				config.PrevoteBlocksMultiple = 5;
				config.VotingSetGrouping = votingSetGrouping;
				return CreateFinalizationOrchestratorServiceRegistrar(config);
			}

			static auto CreateRegistrar() {
				return CreateRegistrar(Default_Voting_Set_Grouping);
			}
		};

		class TestContext : public test::VoterSeededCacheDependentServiceLocatorTestContext<FinalizationOrchestratorServiceTraits> {
		private:
			static constexpr uint64_t Voting_Key_Dilution = FinalizationOrchestratorServiceTraits::Voting_Key_Dilution;

		public:
			TestContext() : TestContext(Default_Round)
			{}

			explicit TestContext(const model::FinalizationRound& orchestratorStartRound, VoterType voterType = VoterType::Large1)
					: m_createCompletedRound(false)
					, m_hashes(test::GenerateRandomDataVector<Hash256>(3)) {
				// note: current voting round (8) is ahead of last round resulting in finalization (5)

				// set up filesystem
				const auto& userConfig = testState().state().config().User;
				const_cast<std::string&>(userConfig.DataDirectory) = m_directoryGuard.name();

				// - nest VotingKeysDirectory under DataDirectory for testing so that it automatically gets cleaned up
				auto dataDirectory = config::CatapultDataDirectory(userConfig.DataDirectory);
				auto votingKeysDirectory = dataDirectory.dir("voting");
				boost::filesystem::create_directories(votingKeysDirectory.path());
				const_cast<std::string&>(userConfig.VotingKeysDirectory) = votingKeysDirectory.str();

				SeedVotingPrivateKeyTree(votingKeysDirectory, keyPairDescriptor(voterType).VotingKeyPair);
				SeedVotingStatus(dataDirectory.rootDir(), orchestratorStartRound);

				// register hooks
				auto pHooks = std::make_shared<FinalizationServerHooks>();
				pHooks->setMessageRangeConsumer([&messages = m_messages](auto&& messageRange) {
					auto extractedMessages = model::FinalizationMessageRange::ExtractEntitiesFromRange(std::move(messageRange.Range));
					messages.insert(messages.end(), extractedMessages.cbegin(), extractedMessages.cend());
				});
				locator().registerRootedService("fin.hooks", pHooks);

				// register storage
				auto lastFinalizedHeightHashPair = model::HeightHashPair{ Height(244), m_hashes[0] };
				auto pProofStorage = std::make_unique<mocks::MockProofStorage>(
						Finalization_Epoch - FinalizationEpoch(1),
						FinalizationPoint(5),
						lastFinalizedHeightHashPair.Height,
						lastFinalizedHeightHashPair.Hash);
				m_pProofStorageRaw = pProofStorage.get();
				locator().registerRootedService("fin.proof.storage", std::make_shared<io::ProofStorageCache>(std::move(pProofStorage)));

				// register aggregator
				m_pAggregator = std::make_shared<chain::MultiRoundMessageAggregator>(
						10'000'000,
						model::FinalizationRound{ Finalization_Epoch - FinalizationEpoch(2), FinalizationPoint(1) },
						lastFinalizedHeightHashPair,
						[this, voterType](const auto& round) {
							auto pRoundMessageAggregator = std::make_unique<mocks::MockRoundMessageAggregator>(round);
							if (m_createCompletedRound) {
								pRoundMessageAggregator->roundContext().acceptPrevote(Height(244), m_hashes.data(), m_hashes.size(), 750);
								pRoundMessageAggregator->roundContext().acceptPrecommit(Height(245), m_hashes[1], 400);
								pRoundMessageAggregator->roundContext().acceptPrecommit(Height(246), m_hashes[2], 400);
							}

							auto stepIdentifier = model::StepIdentifier{ round.Epoch, round.Point, model::FinalizationStage::Prevote };
							auto hash = test::GenerateRandomByteArray<Hash256>();
							auto pMessage = createMessage(voterType, stepIdentifier, Height(245), hash);

							chain::RoundMessageAggregator::UnknownMessages messages;
							messages.push_back(std::move(pMessage));
							pRoundMessageAggregator->setMessages(std::move(messages));
							return pRoundMessageAggregator;
						});
				locator().registerRootedService("fin.aggregator.multiround", m_pAggregator);
			}

			~TestContext() {
				// destroy service, which holds open voting_private_key_tree.dat file handle, before removing temp directory
				destroy();
			}

		public:
			const auto& hashes() const {
				return m_hashes;
			}

			auto& proofStorage() {
				return *m_pProofStorageRaw;
			}

			const auto& aggregator() const {
				return *m_pAggregator;
			}

			const auto& messages() const {
				return m_messages;
			}

			auto votingStatus() {
				const auto& userConfig = testState().state().config().User;
				auto votingStatusFilename = config::CatapultDataDirectory(userConfig.DataDirectory).rootDir().file("voting_status.dat");
				return VotingStatusFile(votingStatusFilename).load();
			}

		public:
			void createCompletedRound() {
				m_createCompletedRound = true;
			}

			void setHash(size_t index, const Hash256& hash) {
				m_hashes[index] = hash;
			}

			void initialize() {
				auto votingRound = Default_Round;
				auto aggregatorModifier = m_pAggregator->modifier();
				aggregatorModifier.setMaxFinalizationRound(votingRound);
				aggregatorModifier.add(test::CreateMessage(votingRound));

				// trigger creation of additional round aggregators to better test pruning
				for (auto i = 0u; i < 3; ++i) {
					auto epoch = Finalization_Epoch - FinalizationEpoch(i);
					for (auto j = 0u; j < 3; ++j)
						aggregatorModifier.add(test::CreateMessage({ epoch, FinalizationPoint(j + 1) }));
				}
			}

		private:
			static auto CreateBmKeyIdentifier(FinalizationEpoch epoch, model::FinalizationStage stage) {
				return model::StepIdentifierToBmKeyIdentifier({ epoch, FinalizationPoint(), stage }, Voting_Key_Dilution);
			}

			static void SeedVotingPrivateKeyTree(const config::CatapultDirectory& directory, const crypto::VotingKeyPair& votingKeyPair) {
				for (auto i = 1u; i <= 4u; ++i) {
					auto treeFilename = directory.file("private_key_tree" + std::to_string(i) + ".dat");
					io::FileStream treeStream(io::RawFile(treeFilename, io::OpenMode::Read_Write));

					auto startKeyIdentifier = CreateBmKeyIdentifier(FinalizationEpoch((i - 1) * 4 + 1), Prevote_Stage);
					auto endKeyIdentifier = CreateBmKeyIdentifier(FinalizationEpoch(i * 4), Precommit_Stage);
					auto bmOptions = crypto::BmOptions{ Voting_Key_Dilution, startKeyIdentifier, endKeyIdentifier };
					crypto::BmPrivateKeyTree::Create(test::CopyKeyPair(votingKeyPair), treeStream, bmOptions);
				}
			}

			static void SeedVotingStatus(const config::CatapultDirectory& directory, const model::FinalizationRound& round) {
				auto votingStatusFilename = directory.file("voting_status.dat");
				VotingStatusFile(votingStatusFilename).save({ round, false, false });
			}

		private:
			bool m_createCompletedRound;
			std::vector<Hash256> m_hashes;

			mocks::MockProofStorage* m_pProofStorageRaw;
			std::shared_ptr<chain::MultiRoundMessageAggregator> m_pAggregator;
			std::vector<std::shared_ptr<model::FinalizationMessage>> m_messages;

			test::TempDirectoryGuard m_directoryGuard;
		};
	}

	// endregion

	// region basic

	ADD_SERVICE_REGISTRAR_INFO_TEST(FinalizationOrchestrator, Post_Extended_Range_Consumers)

	TEST(TEST_CLASS, OrchestratorServiceIsRegistered) {
		// Arrange:
		TestContext context;

		// Act:
		context.boot();

		// Assert:
		EXPECT_EQ(1u + Num_Dependent_Services, context.locator().numServices());
		EXPECT_EQ(0u, context.locator().counters().size());

		// - service (get does not throw)
		context.locator().service<void>("fin.orchestrator");
	}

	TEST(TEST_CLASS, TasksAreRegistered) {
		test::AssertRegisteredTasks(TestContext(), { "finalization task" });
	}

	// endregion

	// region task

	namespace {
		template<typename TCheckState>
		void RunFinalizationTaskTest(TestContext& context, size_t numRepetitions, uint64_t votingSetGrouping, TCheckState checkState) {
			// Arrange:
			context.initialize();
			context.boot(votingSetGrouping);

			test::RunTaskTestPostBoot(context, 1, "finalization task", [&context, numRepetitions, checkState](const auto& task) {
				// Act: run task multiple times
				std::vector<thread::TaskResult> taskResults;
				for (auto i = 0u; i < numRepetitions; ++i)
					taskResults.push_back(task.Callback().get());

				// Assert:
				for (auto i = 0u; i < numRepetitions; ++i)
					EXPECT_EQ(thread::TaskResult::Continue, taskResults[i]) << "result at " << i;

				checkState(context.aggregator(), context.proofStorage(), context.messages());
			});
		}

		void AssertNoMessages(
				const mocks::MockProofStorage& storage,
				const std::vector<std::shared_ptr<model::FinalizationMessage>>& messages) {
			// Assert: storage wasn't called
			EXPECT_TRUE(storage.savedProofDescriptors().empty());

			// - no messages were sent
			EXPECT_TRUE(messages.empty());
		}

		void AssertTwoMessages(
				uint32_t epoch,
				const Hash256& expectedHash,
				const mocks::MockProofStorage& storage,
				const std::vector<std::shared_ptr<model::FinalizationMessage>>& messages) {
			// Assert: storage was called
			const auto& savedProofDescriptors = storage.savedProofDescriptors();
			ASSERT_EQ(1u, savedProofDescriptors.size());
			EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), savedProofDescriptors[0].Round);
			EXPECT_EQ(Height(245), savedProofDescriptors[0].Height);
			EXPECT_EQ(expectedHash, savedProofDescriptors[0].Hash);

			// - two messages were sent
			ASSERT_EQ(2u, messages.size());
			EXPECT_EQ(test::CreateStepIdentifier(epoch, 8, Prevote_Stage), messages[0]->StepIdentifier);
			EXPECT_EQ(test::CreateStepIdentifier(epoch, 8, Precommit_Stage), messages[1]->StepIdentifier);
		}
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereAreNoPendingFinalizedBlocks) {
		// Arrange:
		TestContext context;

		RunFinalizationTaskTest(context, 5, Default_Voting_Set_Grouping, [&context](
				const auto& aggregator,
				const auto& storage,
				const auto& messages) {
			// Assert: check aggregator (no blocks were finalized, so no rounds were pruned)
			auto epoch = Finalization_Epoch.unwrap();
			EXPECT_EQ(test::CreateFinalizationRound(epoch - 2, 1), aggregator.view().minFinalizationRound());
			EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), aggregator.view().maxFinalizationRound());

			// - no messages were sent
			AssertNoMessages(storage, messages);

			// - voting status wasn't changed
			auto votingStatus = context.votingStatus();
			EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), votingStatus.Round);
			EXPECT_FALSE(votingStatus.HasSentPrevote);
			EXPECT_FALSE(votingStatus.HasSentPrecommit);
		});
	}

	namespace {
		void AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocks(
				size_t numRepetitions,
				const model::FinalizationRound& expectedAggregatorMaxRound,
				const model::FinalizationRound& expectedVotingStatusMaxRound) {
			// Arrange:
			TestContext context;
			context.createCompletedRound();

			// - override the storage hash so that it matches
			auto& blockStorage = context.testState().state().storage();
			mocks::SeedStorageWithFixedSizeBlocks(blockStorage, 1200);
			context.setHash(1, blockStorage.view().loadBlockElement(Height(245))->EntityHash);

			RunFinalizationTaskTest(context, numRepetitions, Default_Voting_Set_Grouping, [&](
					const auto& aggregator,
					const auto& storage,
					const auto& messages) {
				// Assert: check aggregator
				auto epoch = Finalization_Epoch.unwrap();
				EXPECT_EQ(test::CreateFinalizationRound(epoch - 1, 1), aggregator.view().minFinalizationRound());
				EXPECT_EQ(expectedAggregatorMaxRound, aggregator.view().maxFinalizationRound());

				// - two messages were sent
				AssertTwoMessages(epoch, context.hashes()[1], storage, messages);

				// - voting status was changed
				auto votingStatus = context.votingStatus();
				EXPECT_EQ(expectedVotingStatusMaxRound, votingStatus.Round);
				EXPECT_FALSE(votingStatus.HasSentPrevote);
				EXPECT_FALSE(votingStatus.HasSentPrecommit);
			});
		}
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereArePendingFinalizedBlocks_OnePoll) {
		// Assert: aggregator is updated at start of task, but voting status is updated at end of task
		AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocks(
				1,
				test::CreateFinalizationRound(6, 8),
				test::CreateFinalizationRound(6, 9));
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereArePendingFinalizedBlocks_MultiplePolls) {
		// Assert: on second task execution, storage and orchestrator have same epoch but height is not at end of epoch,
		//         so epoch is not advanced
		AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocks(
				5,
				test::CreateFinalizationRound(6, 9),
				test::CreateFinalizationRound(6, 9));
	}

	namespace {
		void AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocksWithIneligibleServiceVoter(
				size_t numRepetitions,
				const model::FinalizationRound& expectedAggregatorMaxRound,
				const model::FinalizationRound& expectedVotingStatusMaxRound) {
			// Arrange:
			TestContext context(Default_Round, VoterType::Ineligible);
			context.createCompletedRound();

			// - override the storage hash so that it matches
			auto& blockStorage = context.testState().state().storage();
			mocks::SeedStorageWithFixedSizeBlocks(blockStorage, 1200);
			context.setHash(1, blockStorage.view().loadBlockElement(Height(245))->EntityHash);

			RunFinalizationTaskTest(context, numRepetitions, Default_Voting_Set_Grouping, [&](
					const auto& aggregator,
					const auto& storage,
					const auto& messages) {
				// Assert: check aggregator
				auto epoch = Finalization_Epoch.unwrap();
				EXPECT_EQ(test::CreateFinalizationRound(epoch - 1, 1), aggregator.view().minFinalizationRound());
				EXPECT_EQ(expectedAggregatorMaxRound, aggregator.view().maxFinalizationRound());

				// Assert: storage was called
				const auto& savedProofDescriptors = storage.savedProofDescriptors();
				ASSERT_EQ(1u, savedProofDescriptors.size());
				EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), savedProofDescriptors[0].Round);
				EXPECT_EQ(Height(245), savedProofDescriptors[0].Height);
				EXPECT_EQ(context.hashes()[1], savedProofDescriptors[0].Hash);

				// - no messages were sent
				EXPECT_TRUE(messages.empty());

				// - voting status was changed
				auto votingStatus = context.votingStatus();
				EXPECT_EQ(expectedVotingStatusMaxRound, votingStatus.Round);
				EXPECT_FALSE(votingStatus.HasSentPrevote);
				EXPECT_FALSE(votingStatus.HasSentPrecommit);
			});
		}
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereArePendingFinalizedBlocksWithIneligibleServiceVoter_OnePoll) {
		// Assert: aggregator is updated at start of task, but voting status is updated at end of task
		AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocksWithIneligibleServiceVoter(
				1,
				test::CreateFinalizationRound(6, 8),
				test::CreateFinalizationRound(6, 9));
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereArePendingFinalizedBlocksWithIneligibleServiceVoter_MultiplePolls) {
		// Assert: on second task execution, storage and orchestrator have same epoch but height is not at end of epoch,
		//         so epoch is not advanced
		AssertCanRunFinalizationTaskWhenThereArePendingFinalizedBlocksWithIneligibleServiceVoter(
				5,
				test::CreateFinalizationRound(6, 9),
				test::CreateFinalizationRound(6, 9));
	}

	namespace {
		void AssertCanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch(uint32_t numBlocks) {
			// Arrange:
			TestContext context;
			context.createCompletedRound();
			mocks::SeedStorageWithFixedSizeBlocks(context.testState().state().storage(), numBlocks);

			RunFinalizationTaskTest(context, 2, Small_Voting_Set_Grouping, [&context](
					const auto& aggregator,
					const auto& storage,
					const auto& messages) {
				// - check aggregator (it did not advance the epoch)
				auto epoch = Finalization_Epoch.unwrap();
				EXPECT_EQ(test::CreateFinalizationRound(epoch - 1, 1), aggregator.view().minFinalizationRound());
				EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), aggregator.view().maxFinalizationRound());

				// - two messages were sent
				AssertTwoMessages(epoch, context.hashes()[1], storage, messages);

				// - voting status was changed
				auto votingStatus = context.votingStatus();
				EXPECT_EQ(test::CreateFinalizationRound(epoch, 9), votingStatus.Round);
				EXPECT_FALSE(votingStatus.HasSentPrevote);
				EXPECT_FALSE(votingStatus.HasSentPrecommit);
			});
		}
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch_InsufficientChainHeight) {
		AssertCanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch(196);
		AssertCanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch(244);
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch_IncorrectHashInStorage) {
		AssertCanRunFinalizationTaskWhenThereIsPendingInconsistentFinalizedEpoch(245);
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenThereIsPendingFinalizedEpoch) {
		// Arrange:
		TestContext context;
		context.createCompletedRound();

		// - override the storage hash so that it matches
		auto& blockStorage = context.testState().state().storage();
		mocks::SeedStorageWithFixedSizeBlocks(blockStorage, 245);
		context.setHash(1, blockStorage.view().loadBlockElement(Height(245))->EntityHash);

		RunFinalizationTaskTest(context, 2, Small_Voting_Set_Grouping, [&context](
				const auto& aggregator,
				const auto& storage,
				const auto& messages) {
			// - check aggregator (it advanced the epoch)
			auto epoch = Finalization_Epoch.unwrap();
			EXPECT_EQ(test::CreateFinalizationRound(epoch - 1, 1), aggregator.view().minFinalizationRound());
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 1, 1), aggregator.view().maxFinalizationRound());

			// - two messages were sent
			AssertTwoMessages(epoch, context.hashes()[1], storage, messages);

			// - voting status was changed
			auto votingStatus = context.votingStatus();
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 1, 1), votingStatus.Round);
			EXPECT_FALSE(votingStatus.HasSentPrevote);
			EXPECT_FALSE(votingStatus.HasSentPrecommit);
		});
	}

	namespace {
		void AssertCanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent(uint32_t numBlocks) {
			// Arrange:
			TestContext context({ Finalization_Epoch - FinalizationEpoch(3), FinalizationPoint(8) });
			mocks::SeedStorageWithFixedSizeBlocks(context.testState().state().storage(), numBlocks);

			// - set the storage epoch ahead of the voting epoch (but with an inconsistent hash)
			context.proofStorage().setLastFinalization(Finalization_Epoch, FinalizationPoint(7), Height(245), context.hashes()[0]);

			RunFinalizationTaskTest(context, 2, Small_Voting_Set_Grouping, [&context](
					const auto& aggregator,
					const auto& storage,
					const auto& messages) {
				// - check aggregator (it was not changed)
				auto epoch = Finalization_Epoch.unwrap();
				EXPECT_EQ(test::CreateFinalizationRound(epoch - 2, 1), aggregator.view().minFinalizationRound());
				EXPECT_EQ(test::CreateFinalizationRound(epoch, 8), aggregator.view().maxFinalizationRound());

				// - no messages were sent
				AssertNoMessages(storage, messages);

				// - voting status was not changed
				auto votingStatus = context.votingStatus();
				EXPECT_EQ(test::CreateFinalizationRound(epoch - 3, 8), votingStatus.Round);
				EXPECT_FALSE(votingStatus.HasSentPrevote);
				EXPECT_FALSE(votingStatus.HasSentPrecommit);
			});
		}
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent_InsufficientChainHeight) {
		AssertCanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent(170);
		AssertCanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent(244);
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent_IncorrectHashInStorage) {
		AssertCanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorButInconsistent(245);
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenProofStorageIsAheadOfOrchestratorAndConsistent) {
		// Arrange:
		TestContext context({ Finalization_Epoch - FinalizationEpoch(3), FinalizationPoint(8) });

		// - override the storage hash so that it matches
		auto& blockStorage = context.testState().state().storage();
		mocks::SeedStorageWithFixedSizeBlocks(blockStorage, 245);
		context.setHash(0, blockStorage.view().loadBlockElement(Height(245))->EntityHash);

		// - set the storage epoch ahead of the voting epoch
		context.proofStorage().setLastFinalization(Finalization_Epoch, FinalizationPoint(7), Height(245), context.hashes()[0]);

		RunFinalizationTaskTest(context, 2, Small_Voting_Set_Grouping, [&context](
				const auto& aggregator,
				const auto& storage,
				const auto& messages) {
			// - check aggregator (it advanced the epoch BUT no blocks were finalized, so no rounds were pruned)
			auto epoch = Finalization_Epoch.unwrap();
			EXPECT_EQ(test::CreateFinalizationRound(epoch - 2, 1), aggregator.view().minFinalizationRound());
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 1, 1), aggregator.view().maxFinalizationRound());

			// - no messages were sent
			AssertNoMessages(storage, messages);

			// - voting status was changed
			auto votingStatus = context.votingStatus();
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 1, 1), votingStatus.Round);
			EXPECT_FALSE(votingStatus.HasSentPrevote);
			EXPECT_FALSE(votingStatus.HasSentPrecommit);
		});
	}

	TEST(TEST_CLASS, CanRunFinalizationTaskWhenProofStorageIsBehindOrchestrator) {
		// Arrange:
		TestContext context({ Finalization_Epoch + FinalizationEpoch(2), FinalizationPoint(8) });

		// - override the storage hash so that it matches
		auto& blockStorage = context.testState().state().storage();
		mocks::SeedStorageWithFixedSizeBlocks(blockStorage, 245);
		context.setHash(0, blockStorage.view().loadBlockElement(Height(245))->EntityHash);

		// - set the storage epoch behind the voting epoch
		context.proofStorage().setLastFinalization(Finalization_Epoch, FinalizationPoint(7), Height(245), context.hashes()[0]);

		RunFinalizationTaskTest(context, 2, Small_Voting_Set_Grouping, [&context](
				const auto& aggregator,
				const auto& storage,
				const auto& messages) {
			// - check aggregator (it was not changed)
			auto epoch = Finalization_Epoch.unwrap();
			EXPECT_EQ(test::CreateFinalizationRound(epoch - 2, 1), aggregator.view().minFinalizationRound());
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 2, 8), aggregator.view().maxFinalizationRound());

			// - no messages were sent
			AssertNoMessages(storage, messages);

			// - voting status was not changed
			auto votingStatus = context.votingStatus();
			EXPECT_EQ(test::CreateFinalizationRound(epoch + 2, 8), votingStatus.Round);
			EXPECT_FALSE(votingStatus.HasSentPrevote);
			EXPECT_FALSE(votingStatus.HasSentPrecommit);
		});
	}

	// endregion
}}
