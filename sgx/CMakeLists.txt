project(softhsm_hardtoken_sgx)

set(INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/../common
        ${PROJECT_SOURCE_DIR}/../pkcs11
        ${PROJECT_SOURCE_DIR}/../object_store
        ${PROJECT_SOURCE_DIR}/../data_mgr
        ${PROJECT_SOURCE_DIR}/../crypto
        ${PROJECT_SOURCE_DIR}/../slot_mgr
        )

set(SOURCES TokenModule.cpp
        Token.cpp
        ObjectHandler.cpp
        CryptoHandler.cpp
        KeyHandler.cpp
        )

include_directories(${INCLUDE_DIRS})

set(CPPFLAGS "-D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "-fvisibility=hidden -fpie -fpic -fstack-protector -Wformat -Wformat-security -std=c11 -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fstack-protector -Wformat -Wformat-security -fpie -O2")
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_library(${PROJECT_NAME}-obj OBJECT ${SOURCES} )
add_library(${PROJECT_NAME} SHARED ${SOURCES})
