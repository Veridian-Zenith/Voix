#ifndef PAM_UTILS_H
#define PAM_UTILS_H

#include <security/pam_appl.h>

namespace Voix {

int pam_conversation(int num_msg, const struct pam_message **msg,
                     struct pam_response **resp, void *appdata_ptr);

} // namespace Voix

#endif // PAM_UTILS_H
