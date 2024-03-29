#pragma once
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <emp-ag2pc/emp-ag2pc.h>
#include <boost/multiprecision/cpp_int.hpp>

emp::Integer rerandomize(emp::Integer, std::vector<emp::Integer>, std::vector<emp::Integer>);
emp::Integer dec(std::vector<emp::Integer>, std::vector<emp::Integer>);
emp:: Integer hash(emp::Integer);