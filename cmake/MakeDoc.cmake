# -------------------------------------------------------------------------------------------------- #
# генерация документации (только для UNIX)
# -------------------------------------------------------------------------------------------------- #
find_program( PANDOC pandoc )
find_program( SED sed )
find_program( DOXYGEN doxygen )
find_program( XELATEX xelatex )
find_program( QHELPGENERATOR qhelpgenerator )
find_program( ETAGS etags )
find_program( GZIP gzip )

if( UNIX )
  set( script ${CMAKE_BINARY_DIR}/make-doc-${FULL_VERSION}.sh )
  file( WRITE ${script} "#/bin/bash\n" )
  
  if( PANDOC )
   # определяем команду для генерации man файла
    file( APPEND ${script} "echo Create documentation for aktool utility\n" )
    file( APPEND ${script}
     "pandoc --metadata=date:\"18 July 2021\" --metadata=title:\"aktool\" --metadata=section:1 --metadata=footer:\"Правила пользования\" -s -t man ${CMAKE_SOURCE_DIR}/aktool/Readme.md -o ${CMAKE_SOURCE_DIR}/aktool/aktool.1\n" )
    if( GZIP )
      file( APPEND ${script} "gzip --force ${CMAKE_SOURCE_DIR}/aktool/aktool.1\n" )
    endif()
    file( APPEND ${script} "echo Ok\n" )
  endif()

  # документация для функций библиотеки
  if( DOXYGEN )
    # doxygen найден и документация может быть сгенерирована
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.akbase.in ${CMAKE_BINARY_DIR}/Doxyfile.akbase @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/libakbase-header.tex.in ${CMAKE_BINARY_DIR}/libakbase-header.tex @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/Doxyfile.akrypt.in ${CMAKE_BINARY_DIR}/Doxyfile.akrypt @ONLY )
    configure_file( ${CMAKE_SOURCE_DIR}/doc/libakrypt-header.tex.in ${CMAKE_BINARY_DIR}/libakrypt-header.tex @ONLY )

    file( APPEND ${script} "doxygen Doxyfile.akbase\n" )
    file( APPEND ${script} "doxygen Doxyfile.akrypt\n" )

    if( XELATEX )
      file( APPEND ${script} "cd doc-akbase/latex; make; cd ../..\n" )
      file( APPEND ${script} "cp doc-akbase/latex/refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.pdf\n")
      file( APPEND ${script} "cd doc-akrypt/latex; make; cd ../..\n" )
      file( APPEND ${script} "cp doc-akrypt/latex/refman.pdf ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf\n")
    endif()

    if( QHELPGENERATOR )
      file( APPEND ${script} "cp doc-akbase/html/akbase-library.qch ${CMAKE_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akbase/html/akbase-library.qch\n" )
      file( APPEND ${script} "cp doc-akrypt/html/akrypt-library.qch ${CMAKE_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.qch\n" )
      file( APPEND ${script} "rm doc-akrypt/html/akrypt-library.qch\n" )
    endif()
    file( APPEND ${script} "tar -cjvf libakrypt-base-doc-${FULL_VERSION}.tar.bz2 doc-akbase/html\n")
    file( APPEND ${script} "tar -cjvf libakrypt-doc-${FULL_VERSION}.tar.bz2 doc-akrypt/html\n")
  else()
      message("-- doxygen not found")
  endif()

  if( ETAGS )
    file( APPEND ${script} "cd ${CMAKE_SOURCE_DIR}; etags.emacs source/*.[ch]; cd ${CMAKE_BINARY_DIR}\n" )
  endif()

  execute_process( COMMAND chmod +x ${script} )
  add_custom_target( doc ${script} )
  message("-- Script for documentation is done (now \"make doc\" enabled)")
endif()

