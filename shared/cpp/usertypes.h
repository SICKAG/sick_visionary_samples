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

  ThreeLevels(int value)
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

  std::string to_string() const
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

private:
  ThreeLevelsEnum level;
};

class BinningOption
{
public:
  enum BinningOptionEnum
  {
    NONE = 0,
    TWO_BY_TWO   = 1,
    FOUR_BY_FOUR = 2,
  };

  BinningOption(int value)
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

  operator int() const
    {
        return static_cast<int>(level);
    }

  std::string to_str() const
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

  private:
    BinningOptionEnum level;
};

} // namespace UserTypes

} // namespace visionary

#endif // USERTYPES_H_INCLUDED
