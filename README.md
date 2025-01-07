g++ -o verify verify.cpp -I./Inc -L./Lib -lNBioBSP -lstdc++

g++ -o fingerprint_app test.cpp -I./Inc -L./Lib -lNBioBSP -lstdc++

python .\test.py
