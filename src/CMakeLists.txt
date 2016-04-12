#
#
# stunclient, network path trace


set (ADDITIONAL_LIBS "")

#find_package( OpenSSL )
#if( OPENSSL_FOUND )
#  include_directories( ${OPENSSL_INCLUDE_DIR} )
#  list(APPEND ADDITIONAL_LIBS ${OPENSSL_LIBRARIES})
#endif( OPENSSL_FOUND )



add_executable ( stunclient
                 ${version_file}
                 iphelper.c
                 sockethelper.c
                 utils.c
                 stunclient.c )

target_link_libraries ( stunclient PRIVATE
                        sockaddrutil
                        stunlib
                        pthread
                        ${ADDITIONAL_LIBS})

set_target_properties(stunclient PROPERTIES INSTALL_RPATH "${install_dir}/lib")
set_target_properties(stunclient PROPERTIES BUILD_WITH_INSTALL_RPATH ON)

include_directories ( ../include )
link_directories ( ${CHECK_LIBRARY_DIRS} )

set (crusty_files
     stunclient.c
     iphelper.c
     sockethelper.c)

UncrustifyDir(crusty_files)
