cmake_minimum_required(VERSION 3.14)

catapult_define_tool(testvectors)
target_link_libraries(catapult.tools.testvectors catapult.crypto_voting)
