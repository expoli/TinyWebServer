cmake_minimum_required(VERSION 3.8)

project(TinyWebServer)

add_link_options(-lpthread -lmysqlclient)

set(SRC main.cpp
        ./timer/lst_timer.cpp ./timer/lst_timer.h
        ./http/http_conn.cpp ./http/http_conn.h
        ./threadpool/threadpool.h
        ./log/log.cpp ./log/log.h
        ./CGImysql/sql_connection_pool.cpp ./CGImysql/sql_connection_pool.h
        webserver.h webserver.cpp
        config.cpp config.h
        )

option(BUILD_DEBUG_MODE "build server with debug mode?" OFF)

if (BUILD_DEBUG_MODE)
    add_compile_options(-g)
endif ()

add_compile_options(-O2)

add_executable(server ${SRC})
