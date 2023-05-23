export CFLAGS='-fsanitize=address'
export CXXFLAGS='-fsanitize=address'
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -GNinja && cmake --build .
