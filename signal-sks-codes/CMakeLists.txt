cmake_minimum_required(VERSION 3.10)

# project details
project(SignalApp VERSION 1.0)
set(EXEC_NAME signal_app)
set(LIBRARY_NAME signal_app_lib)
set(LIBRARY_NAME_SHARED signal_app_lib_shared)

# packages
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
include(Boost)
# include(Cryptopp)
include(CTest)
include(Doctest)
include(Documentation)
include(Warnings)
include(Curses)

# add shared libraries
set(SOURCES_SHARED src-shared/messages.cxx src-shared/logger.cxx src-shared/util.cxx ${PROJECT_SOURCE_DIR}/kyber/ref/randombytes.c)
add_library(${LIBRARY_NAME_SHARED} ${SOURCES_SHARED})
target_include_directories(${LIBRARY_NAME_SHARED} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PUBLIC doctest)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp)
# target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE cryptopp-shared)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${Boost_LIBRARIES})
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${CURSES_LIBRARIES})

target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${PROJECT_SOURCE_DIR}/kyber/ref/libpqcrystals_kyber512_ref.so)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${PROJECT_SOURCE_DIR}/kyber/ref/libpqcrystals_aes256ctr_ref.so)
target_link_libraries(${LIBRARY_NAME_SHARED} PRIVATE ${PROJECT_SOURCE_DIR}/kyber/ref/libpqcrystals_fips202_ref.so)


# add student libraries
set(SOURCES
  src/pkg/client.cxx
  src/pkg/onion_client.cxx
  src/drivers/crypto_driver.cxx
  src/drivers/network_driver.cxx
  src/drivers/cli_driver.cxx)
add_library(${LIBRARY_NAME} ${SOURCES})
target_include_directories(${LIBRARY_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include-shared ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${LIBRARY_NAME} PRIVATE ${LIBRARY_NAME_SHARED})

# add executables
add_executable(${EXEC_NAME} src/cmd/main.cxx)
target_link_libraries(${EXEC_NAME} PRIVATE ${LIBRARY_NAME})

# properties
set_target_properties(
  ${LIBRARY_NAME} ${LIBRARY_NAME_SHARED} ${EXEC_NAME}
    PROPERTIES
      CXX_STANDARD 17
      CXX_STANDARD_REQUIRED YES
      CXX_EXTENSIONS NO
)

# add tests
add_subdirectory(test)
add_custom_target(check ./test.sh)
