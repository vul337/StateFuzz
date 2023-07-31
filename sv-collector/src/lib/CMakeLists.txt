set (KASource
  Flags.h
  Common.h
  Common.cpp
  Global.h
  KAMain.cpp
  Annotation.h
  Annotation.cpp
  StructAnalyzer.h
  StructAnalyzer.cpp
  CallGraph.h
  CallGraph.cpp
  CRange.h
  Range.h
  Range.cpp
  StateVariableAnalysis.cpp
  StateVariableAnalysis.h
)

# Build libraries.
add_library (KAObj OBJECT ${KASource})
# add_library (KAShared SHARED $<TARGET_OBJECTS:KAObj>)
add_library (KAStatic STATIC $<TARGET_OBJECTS:KAObj>)

# Build executable, KAMain.
set (EXECUTABLE_OUTPUT_PATH ${KA_BINARY_DIR})
link_directories (${KA_BINARY_DIR}/lib)
add_executable(KAMain ${KASource})
target_link_libraries(KAMain 
  LLVMAsmParser
  LLVMSupport
  LLVMCore
  LLVMAnalysis
  LLVMIRReader
  KAStatic
  )
