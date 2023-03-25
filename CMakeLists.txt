cmake_minimum_required(VERSION 3.8)

project(TinyWebServer)

add_link_options(-lpthread -lmysqlclient)

set(SRC main.cpp  ./timer/lst_timer.cpp ./http/http_conn.cpp ./log/log.cpp ./CGImysql/sql_connection_pool.cpp  webserver.cpp config.cpp)

option(BUILD_DEBUG_MODE "build server with debug mode?" OFF)

if (BUILD_DEBUG_MODE)
    add_compile_options(-g)
endif ()

add_compile_options(-O2)

add_executable(server ${SRC})
