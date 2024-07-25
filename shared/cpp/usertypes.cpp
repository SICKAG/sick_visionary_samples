//
// Copyright (c) 2024 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include "usertypes.h"

// Definitions of the methods in the ThreeLevels class
visionary::UserTypes::ThreeLevels::ThreeLevels(int value)
{
  switch (value)
  {
    case 0:
      level = ThreeLevelsEnum::INVALID;
      break;
    case 1:
      level = ThreeLevelsEnum::ERROR;
      break;
    case 2:
      level = ThreeLevelsEnum::WARNING;
      break;
    case 3:
      level = ThreeLevelsEnum::GOOD;
      break;
  }
}

std::string visionary::UserTypes::ThreeLevels::to_string() const
{
  switch (level)
  {
    case ThreeLevelsEnum::INVALID:
      return "INVALID";
    case ThreeLevelsEnum::ERROR:
      return "ERROR";
    case ThreeLevelsEnum::WARNING:
      return "WARNING";
    case ThreeLevelsEnum::GOOD:
      return "GOOD";
    default:
      return "UNKNOWN";
  }
}

// Definitions of the methods in the BinningOption class
visionary::UserTypes::BinningOption::BinningOption(int value)
{
  switch (value)
  {
    case 0:
      level = BinningOptionEnum::NONE;
      break;
    case 1:
      level = BinningOptionEnum::TWO_BY_TWO;
      break;
    case 2:
      level = BinningOptionEnum::FOUR_BY_FOUR;
      break;
  }
}

visionary::UserTypes::BinningOption::operator int() const
{
  return static_cast<int>(level);
}

std::string visionary::UserTypes::BinningOption::to_str() const
{
  switch (level)
  {
    case BinningOptionEnum::NONE:
      return "NONE";
    case BinningOptionEnum::TWO_BY_TWO:
      return "TWO_BY_TWO";
    case BinningOptionEnum::FOUR_BY_FOUR:
      return "FOUR_BY_FOUR";
    default:
      return "UNKNOWN";
  }
}
