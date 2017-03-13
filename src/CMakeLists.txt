
#set(ROCKSDB ${PROJECT_SOURCE_DIR}/lib/rocksdb-4.11.2/include)
set(CLOG ${PROJECT_SOURCE_DIR}/lib/c-log-master/src)
include_directories(${CLOG} ${ROCKSDB} ${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src)

set(APP_SRC main.cpp)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(INIPARSELIB ${PROJECT_SOURCE_DIR}/lib/iniparser-master/libiniparser.a)
set(HIREDISLIB ${PROJECT_SOURCE_DIR}/lib/hiredis/libhiredis.a)
# set(ROCKSDB_LIB ${PROJECT_SOURCE_DIR}/lib/rocksdb-4.11.2/librocksdb.a)

# add_definitions("--std==c++11 -pthread -O0 -flto -Wl,--no-as-needed")
# add_definitions("-std=c++11 -g -pthread")
add_definitions("-std=c++11 -o3")
# add_definitions("-DDEBUG")

aux_source_directory(${PROJECT_SOURCE_DIR}/src ALL_SOURCE)

add_executable(main ${APP_SRC} ${ALL_SOURCE})
target_link_libraries(main libclog ${INIPARSELIB} )
target_link_libraries(main libpcap.so)
target_link_libraries(main hiredis ${HIREDISLIB} )
target_link_libraries(main pthread)
#target_link_libraries(main bz2)
#target_link_libraries(main /usr/lib64/libz.so)
#target_link_libraries(main ${ROCKSDB_LIB})

