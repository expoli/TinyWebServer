cmake_minimum_required(VERSION 3.24)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(TinyWebServer VERSION 1.0)

set(SOURCES  main.cpp ./threadpool/threadpool.h ./http/http_conn.cpp ./http/http_conn.h ./lock/locker.h ./log/log.cpp ./log/log.h ./log/block_queue.h ./CGImysql/sql_connection_pool.cpp ./CGImysql/sql_connection_pool.h)
add_link_options(-lpthread -lmysqlclient)

add_executable(server ${SOURCES})

