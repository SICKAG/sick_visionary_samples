//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#ifndef USERTYPES_H_INCLUDED
#define USERTYPES_H_INCLUDED
#include <string>

namespace visionary {

namespace UserTypes {

class ThreeLevels
{
public:
  enum ThreeLevelsEnum
  {
    INVALID = 0,
    ERROR   = 1,
    WARNING = 2,
    GOOD    = 3
  };

  ThreeLevels(int value);
  std::string to_string() const;

private:
  ThreeLevelsEnum level;
};

class BinningOption
{
public:
  enum BinningOptionEnum
  {
    NONE         = 0,
    TWO_BY_TWO   = 1,
    FOUR_BY_FOUR = 2,
  };

  BinningOption(int value);
  operator int() const;
  std::string to_str() const;

private:
  BinningOptionEnum level;
};

} // namespace UserTypes

} // namespace visionary

#endif // USERTYPES_H_INCLUDED
