#include "pam_utils.h"
#include <print>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <cstring>
#include <string>

namespace Voix {

int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr) {
  (void)appdata_ptr;
  struct pam_response *response = nullptr;

  response =
      (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
  if (!response) {
    return PAM_CONV_ERR;
  }

  for (int i = 0; i < num_msg; i++) {
    switch (msg[i]->msg_style) {
    case PAM_PROMPT_ECHO_OFF: {
      struct termios old_term, new_term;
      tcgetattr(STDIN_FILENO, &old_term);
      new_term = old_term;
      new_term.c_lflag &= ~ECHO;
      tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

      std::print("{}", msg[i]->msg);
      std::fflush(stdout);

      char password[512] = {0};
      std::cin.getline(password, sizeof(password));

      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      std::println();

      response[i].resp = strdup(password);
      memset(password, 0, sizeof(password));
      response[i].resp_retcode = 0;
      break;
    }
    case PAM_PROMPT_ECHO_ON:
      std::print("{}", msg[i]->msg);
      std::fflush(stdout);
      {
        std::string input;
        std::getline(std::cin, input);
        response[i].resp = strdup(input.c_str());
        response[i].resp_retcode = 0;
      }
      break;
    case PAM_ERROR_MSG:
      std::println(stderr, "PAM Error: {}", msg[i]->msg);
      response[i].resp_retcode = 0;
      break;
    case PAM_TEXT_INFO:
      std::println("{}", msg[i]->msg);
      response[i].resp_retcode = 0;
      break;
    default:
      free(response);
      return PAM_CONV_ERR;
    }
  }

  *resp = response;
  return PAM_SUCCESS;
}

} // namespace Voix
