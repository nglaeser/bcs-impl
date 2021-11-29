# Blind Conditional Signatures (BCS)

## Dependencies
- `emp-ag2pc`: Follow the instructions [here](https://github.com/emp-toolkit/emp-ag2pc).
- Run `pip install -r requirements.txt`
- [Boost](https://www.boost.org/doc/libs/1_77_0/more/getting_started/index.html)

## Install
```
mkdir build
cd build
cmake ..
cd ..
make -C build main
```

## Usage
To generate the input files:
```
python gen_data.py [-h] [-g G] [-n N]
```
Run with `-h` for more usage information.

To generate the rerandomization circuit:
```
./build/bin/main -c
```
Count AND gates with
```
grep AND circuit.txt | wc -l
```
For more information about the circuit file format, see [here](https://github.com/MPC-SoK/frameworks/wiki/EMP-toolkit#circuit-format).