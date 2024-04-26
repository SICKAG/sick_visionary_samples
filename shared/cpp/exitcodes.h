#ifndef SHARED_EXITCODES_H_INCLUDED
#define SHARED_EXITCODES_H_INCLUDED

/// Sample exit codes
enum class ExitCode : int
{
  eOk                        = 0,                              ///< sample was successful.
  eParamError                = 1,                              ///< invalid parameter value passed to sample program.
  eCommunicationError        = 100,                            ///< network or protocol communication error.
  eControlCommunicationError = eCommunicationError + 0,        ///< communication error on the control channel.
  eControlParameterError     = eControlCommunicationError + 1, ///< invalid parameter value for a method or variable.
  eStreamCommunicationError  = eCommunicationError + 50,       ///< communication error on the image streaming channel.
  eFrameTimeout              = eStreamCommunicationError + 0,  ///< timeout while waiting for a frame.
  eAuthenticationError       = 200                             ///< CoLa device authentication failed.
};

#endif // SHARED_EXITCODES_H_INCLUDED
