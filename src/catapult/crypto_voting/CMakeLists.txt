cmake_minimum_required(VERSION 3.14)

find_package(AMCL REQUIRED)

catapult_library_target(catapult.crypto_voting)
target_link_libraries(catapult.crypto_voting catapult.crypto AMCL::AMCL)
