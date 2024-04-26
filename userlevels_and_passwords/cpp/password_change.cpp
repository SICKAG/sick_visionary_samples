//
// Copyright (c) 2023 SICK AG, Waldkirch
//
// SPDX-License-Identifier: Unlicense

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>

#include <iostream>
#include <random>
#include <sstream>

#include "botan_all.h"
#include "exitcodes.h"

#include "CryptoUtils.h"
#include <AuthenticationSecure.h>
#include <CoLaParameterReader.h>
#include <CoLaParameterWriter.h>
#include <VisionaryControl.h>
#include <VisionaryType.h>

/**
 * @brief Get the challenge from the device
 * @param visionaryControl The VisionaryControl object
 * @return The challenge
 */
visionary::ChallengeRequest getChallengeFromDevice(std::shared_ptr<visionary::VisionaryControl> visionaryControl,
                                                   visionary::ProtocolType                      protocolType)
{
  using namespace visionary;

  ChallengeRequest challengeRequest{};
  // create command to get the challenge
  CoLaParameterWriter getChallengeCommandBuilder =
    CoLaParameterWriter(CoLaCommandType::METHOD_INVOCATION, "GetChallenge");

  if (protocolType == SUL2)
  {
    // build and send the cola command
    CoLaCommand getChallengeCommand =
      getChallengeCommandBuilder.parameterUSInt(static_cast<uint8_t>(IAuthentication::UserLevel::SERVICE)).build();
    CoLaCommand getChallengeResponse = visionaryControl->sendCommand(getChallengeCommand);

    if (getChallengeResponse.getError() != CoLaError::OK)
    {
      std::fprintf(stderr, "Failure when trying to get Challange: %d\n", getChallengeResponse.getError());
    }
    else
    {
      // parse the response
      CoLaParameterReader coLaParameterReader = CoLaParameterReader(getChallengeResponse);
      coLaParameterReader.readUSInt(); // skip result code
      for (std::uint32_t byteCounter = 0u; byteCounter < sizeof(challengeRequest.challenge); byteCounter++)
      {
        challengeRequest.challenge[byteCounter] = coLaParameterReader.readUSInt();
      }
      for (std::uint32_t byteCounter = 0u; byteCounter < sizeof(challengeRequest.salt); byteCounter++)
      {
        challengeRequest.salt[byteCounter] = coLaParameterReader.readUSInt();
      }
    }
  }
  return challengeRequest;
}

bool isAllZeros(const std::vector<uint8_t>& vec)
{
  for (uint8_t element : vec)
  {
    if (element != 0)
    {
      return false; // If any element is non-zero, return false
    }
  }
  return true; // All elements are zero
}

/**
 * @brief Create an encrypted message to change the password
 * @param UserLevelName The UserLevel for which the password should be changed
 * @param oldPassword The old password
 * @param newPassword The new password
 * @param oldSalt The old salt
 * @return The encrypted message
 */
std::vector<uint8_t> createEncryptedMessage(std::string          UserLevelName,
                                            std::string          oldPassword,
                                            std::string          newPassword,
                                            std::vector<uint8_t> oldSalt)
{
  // generate a Hash using the old password
  std::vector<uint8_t> oldPwdString(UserLevelName.begin(), UserLevelName.end());
  appendStringtoBytes(oldPwdString, ":SICK Sensor:");
  appendStringtoBytes(oldPwdString, oldPassword);
  if (!isAllZeros(oldSalt))
  {
    oldPwdString.push_back(':');
    oldPwdString.insert(oldPwdString.end(), oldSalt.begin(), oldSalt.end());
  }
  // has this password string
  auto oldPwdHash = calcSHA256Hash(std::string(oldPwdString.begin(), oldPwdString.end()));

  // create a Hash with the new password and encrypt it using AES128
  std::vector<uint8_t> newPwdString(UserLevelName.begin(), UserLevelName.end());
  appendStringtoBytes(newPwdString, ":SICK Sensor:");
  appendStringtoBytes(newPwdString, newPassword);
  std::vector<uint8_t> newSalt = {0};
  if (!isAllZeros(oldSalt))
  {
    newPwdString.push_back(':');
    // create a random 16 bytes salt vector
    newSalt = generateRandomBytes(16);
    newPwdString.insert(newPwdString.end(), newSalt.begin(), newSalt.end());
  }
  auto newPwdHash = calcSHA256Hash(std::string(newPwdString.begin(), newPwdString.end()));

  // extract a key from the old Password Hash
  std::vector<uint8_t> key(oldPwdHash.begin(), oldPwdHash.begin() + 16);
  // create a random iv
  std::vector<uint8_t> iv = generateRandomBytes(16);

  // encrypt the new password hash and the new salt
  auto encryptData = std::vector<uint8_t>(newPwdHash.begin(), newPwdHash.end());
  if (!isAllZeros(oldSalt))
  {
    encryptData.insert(encryptData.end(), newSalt.begin(), newSalt.end());
  }
  auto encryptedNewPwdHash = encryptWithAES128(key, iv, encryptData, isAllZeros(oldSalt));

  // create a HMAC
  std::vector<uint8_t> hmacData(iv.begin(), iv.end());
  hmacData.insert(hmacData.end(), encryptedNewPwdHash.begin(), encryptedNewPwdHash.end());
  auto generatedHMAC = calculateHMAC(std::vector<uint8_t>(oldPwdHash.begin(), oldPwdHash.end()), hmacData);

  std::vector<uint8_t> bytesToSend(hmacData.begin(), hmacData.end());
  bytesToSend.insert(bytesToSend.end(), generatedHMAC.begin(), generatedHMAC.end());
  return bytesToSend;
}

/**
 * Change password for Secure User Level SUL 1 and SUL2
 * @param visionaryControl The VisionaryControl object
 * @param userLevel The UserLevel for which the password should be changed
 * @param oldPassword The old password
 * @param newPassword The new password
 * @return True if the password was changed successfully, false otherwise
 */
bool changePasswordForUserLevelSecure(std::shared_ptr<visionary::VisionaryControl> visionaryControl,
                                    std::string                                  userLevel,
                                    std::string                                  oldPassword,
                                    std::string                                  newPassword,
                                    visionary::ProtocolType                      SUL)
{
  using namespace visionary;
  // tag::change_password_command[]
  // get challenge from device
  ChallengeRequest challengeRequest = getChallengeFromDevice(visionaryControl, SUL);

  // create an encrypted message from the old password, the user Level, the new password and the old salt
  auto encryptedMessage = createEncryptedMessage(
    userLevel, oldPassword, newPassword, std::vector<uint8_t>(challengeRequest.salt.begin(), challengeRequest.salt.end()));

  // Build the COLA command for changing the password
  CoLaParameterWriter getChangePasswordBuilder =
    CoLaParameterWriter(CoLaCommandType::METHOD_INVOCATION, "ChangePassword");
  getChangePasswordBuilder.parameterUInt(encryptedMessage.size()); // add length of the encrypted message array
  // add the encrypted message to the cola command
  for (auto byte : encryptedMessage)
  {
    getChangePasswordBuilder.parameterUSInt(byte);
  }
  // last parameter in the cola command is the UserLevel
  CoLaCommand getChangePasswordCommand =
    getChangePasswordBuilder.parameterUSInt(static_cast<uint8_t>(IAuthentication::UserLevel::SERVICE)).build();

  // send the cola command
  CoLaCommand getChangePasswordResponse = visionaryControl->sendCommand(getChangePasswordCommand);
  // 0 == SUCCESS see ChangePassword documentation
  uint8_t     result                       = CoLaParameterReader(getChangePasswordResponse).readUSInt(); // 0 == SUCCESS
  if (getChangePasswordResponse.getError() == CoLaError::OK && result == 0)
  {
    std::fprintf(
      stdout, "Changed secure hash for user level %s. PASSWORD: %s\n", userLevel.c_str(), newPassword.c_str());
    return true;
  }
  // end::change_password_command[]
  else
  {
    std::fprintf(stderr, "Failed to change password\n");
    return false;
  }
}

/**
 * Password change for legacy devices (Visionary-S)
 * @param visionaryControl The VisionaryControl object
 * @param userLevel The UserLevel for which the password should be changed
 * @param newPassword The new password
 * @return True if the password was changed successfully, false otherwise
 */
bool changePasswordForUserLevelLegacy(std::shared_ptr<visionary::VisionaryControl> visionaryControl,
                                      std::string                                  userLevel,
                                      std::string                                  newPassword)
{
  using namespace visionary;
  // tag::set_password_command[]
  // Build the cola message for SetPassword method invocation
  CoLaParameterWriter getChangePasswordBuilder = CoLaParameterWriter(CoLaCommandType::METHOD_INVOCATION, "SetPassword");
  // add the UserLevel
  getChangePasswordBuilder.parameterUSInt(static_cast<uint8_t>(IAuthentication::UserLevel::SERVICE));
  // add the MD5 hash to the password
  getChangePasswordBuilder.parameterPasswordMD5(newPassword);
  CoLaCommand getChangePasswordCommand = getChangePasswordBuilder.build();

  CoLaCommand getChangePasswordResponse = visionaryControl->sendCommand(getChangePasswordCommand);
  // 1 == SUCCESS see SetPassword method documentation
  uint8_t     result                    = CoLaParameterReader(getChangePasswordResponse).readUSInt(); 
  if (getChangePasswordResponse.getError() == CoLaError::OK && result == 1)
  {
    std::fprintf(
      stdout, "Changed legacy password hash for user level %s. PASSWORD: %s\n", userLevel.c_str(), newPassword.c_str());
    return true;
  }
  // end::set_password_command[]
  else
  {
    std::fprintf(stderr, "Failed to change the legacy password hash: %d\n", getChangePasswordResponse.getError());
    return false;
  }
}

/**
 * @brief Change the password for a given UserLevel
 * @param visionaryControl The VisionaryControl object
 * @param uLvl The UserLevel for which the password should be changed
 * @param oldPassword The old password
 * @param newPassword The new password
 * @return True if the password was changed successfully, false otherwise
 */
bool changePasswordForUserLevel(std::shared_ptr<visionary::VisionaryControl> visionaryControl,
                                std::string                                  uLvl,
                                std::string                                  oldPassword,
                                std::string                                  newPassword,
                                visionary::VisionaryType                     visionaryType)
{
  // check if device is SUL1/2 or Legacy and call the correct functions for password change
  if (visionaryType == visionary::VisionaryType::eVisionaryTMini)
  {
    return changePasswordForUserLevelSecure(
      visionaryControl, uLvl, oldPassword, newPassword, visionary::ProtocolType::SUL2);
  }
  else
  {
    // for Visionary-S we have to change the password using the legacy method and the secure method using SUL1
    return changePasswordForUserLevelLegacy(visionaryControl, uLvl, newPassword)
           && changePasswordForUserLevelSecure(
             visionaryControl, uLvl, oldPassword, newPassword, visionary::ProtocolType::SUL1);
  }
}

static ExitCode runChangePasswordDemo(visionary::VisionaryType visionaryType, const std::string& ipAddress)
{
  using namespace visionary;
  ExitCode exitcode;

  const std::string userLevel = "Service";
  const std::string oldPassword = "CUST_SERV";
  const std::string newPassword     = "TEST";
  
  // tag::control_connection[]
  std::shared_ptr<VisionaryControl> visionaryControl = std::make_shared<VisionaryControl>(visionaryType);
  if (!visionaryControl->open(ipAddress))
  // end::control_connection[]
  {
    std::fprintf(stderr, "Failed to open control connection to device.\n");
    return ExitCode::eCommunicationError;
  }
 
  // tag::login_old_password[]
  if (!visionaryControl->login(IAuthentication::UserLevel::SERVICE, oldPassword))
  // end::login_old_password[]
  {
    std::fprintf(stderr, "Failed login: Userlvl: %s | Password %s\n", userLevel.c_str(), oldPassword.c_str());

    return ExitCode::eAuthenticationError;
  }
  std::fprintf(stdout, "Successful login: Userlvl: %s | Password %s\n\n", userLevel.c_str(), oldPassword.c_str());

  // tag::change_password[]
  if (!changePasswordForUserLevel(visionaryControl, userLevel, oldPassword, newPassword, visionaryType))
  {
    std::fprintf(stderr, "Failed to change device password for Userlvl %s\n", userLevel.c_str());
    return ExitCode::eAuthenticationError;
  }
  visionaryControl->logout();
  // end::change_password[]
  std::fprintf(stdout, "Logout from device\n\n");

  // We try to login to the userlevel with the old password.
  // We expect an error to occur since we changed the password.
  // tag::wrong_password[]
  std::fprintf(stdout, "1. Login with old password.\n");
  if (!visionaryControl->login(IAuthentication::UserLevel::SERVICE, oldPassword))
  {
    std::fprintf(stderr, "Failed login: Userlvl: %s | Password %s\n\n", userLevel.c_str(), oldPassword.c_str());
  }
  // end::wrong_password[]

  // tag::new_password_login[]
  std::fprintf(stdout, "2. Login with new password.\n");
  if (!visionaryControl->login(IAuthentication::UserLevel::SERVICE, newPassword))
  {
    std::fprintf(stderr, "Failed login: Userlvl: %s | Password %s\n", userLevel.c_str(), newPassword.c_str());

    return ExitCode::eAuthenticationError;
  }
  std::fprintf(stdout, "Successful login: Userlvl: %s | Password %s\n\n", userLevel.c_str(), newPassword.c_str());
  // end::new_password_login[]

  // tag::reset_password[]
  std::fprintf(stdout, "Resetting password.\n");
  if (changePasswordForUserLevel(visionaryControl, "Service", newPassword, oldPassword, visionaryType))
  {
    std::fprintf(stdout, "Successfully reset password.\n\n");
  }
  else
  {
    std::fprintf(stderr, "Failed to reset password.\n");
    return ExitCode::eAuthenticationError;
  }
  // end::reset_password[]

  // tag::logout_and_close[]
  visionaryControl->logout();
  visionaryControl->close();
  // end::logout_and_close[]
  std::fprintf(stdout, "Logout from device\n");
  std::fprintf(stdout, "Closed the connection\n");

  return ExitCode::eOk;
}

int main(int argc, char* argv[])
{
  std::string              deviceIpAddr("192.168.1.10");
  visionary::VisionaryType visionaryType(visionary::VisionaryType::eVisionaryTMini);

  bool showHelpAndExit = false;

  ExitCode exitCode = ExitCode::eOk;

  for (int i = 1; i < argc; ++i)
  {
    std::istringstream argstream(argv[i]);

    if (argstream.get() != '-')
    {
      showHelpAndExit = true;
      exitCode        = ExitCode::eParamError;
      break;
    }
    switch (argstream.get())
    {
      case 'h':
        showHelpAndExit = true;
        break;
      case 'i':
        argstream >> deviceIpAddr;
        break;
      case 't':
      {
        std::string visionaryTypeName;
        argstream >> visionaryTypeName;
        try
        {
          visionaryType = visionary::VisionaryType::fromString(visionaryTypeName);
        }
        catch (const std::invalid_argument& e)
        {
          std::cerr << e.what() << ": '" << visionaryTypeName << "'" << std::endl;
          showHelpAndExit = true;
          exitCode        = ExitCode::eParamError;
        }
      }
      break;
      default:
        showHelpAndExit = true;
        break;
    }
  }

  if (showHelpAndExit)
  {
    std::cout << argv[0] << " [option]*" << std::endl;
    std::cout << "where option is one of" << std::endl;
    std::cout << "-h          show this help and exit" << std::endl;
    std::cout << "-i<IP>      connect to the device with IP address <IP>; "
                 "default is "
              << deviceIpAddr << std::endl;
    std::cout << "-t<typename> visionary product type; default is '" << visionaryType.toString() << std::endl;

    std::cout << "Visionary product types:\n";
    for (const auto& name : visionary::VisionaryType::getNames())
    {
      std::cout << "  " << name << '\n';
    }

    return static_cast<int>(exitCode);
  }

  exitCode = runChangePasswordDemo(visionaryType, deviceIpAddr);

  std::cout << "exit code " << static_cast<int>(exitCode) << std::endl;

  return static_cast<int>(exitCode);
}
