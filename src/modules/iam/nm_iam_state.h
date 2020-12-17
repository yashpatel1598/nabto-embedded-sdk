#ifndef _NM_IAM_STATE_H_
#define _NM_IAM_STATE_H_

#include <nn/llist.h>
#include <nn/string_set.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_iam_user {
    char* username;
    char* displayName;
    char* role;
    char* password;
    char* fingerprint;
    char* sct;
    char* fcmToken;
    struct nn_llist_node listNode;
    struct nn_string_set notificationCategories;
};

struct nm_iam_state {
    struct nn_llist users;
    char* passwordOpenPassword;
    char* passwordOpenSct;
    bool passwordOpenPairing;
    bool localOpenPairing;
    bool passwordInvitePairing;
    bool localInitialPairing;
    char* openPairingRole;
    char* initialPairingUsername;
};

/*****************
 * State Builder *
 *****************/

/**
 * Create IAM state
 *
 * @return NULL iff the state could not be created
 */
struct nm_iam_state* nm_iam_state_new();

/**
 * Free IAM state if the ownership was not transfered to an
 * IAM module with nm_iam_load_state()
 *
 * @param state [in]  State to free
 */
void nm_iam_state_free(struct nm_iam_state* state);

/**
 * Set pairing password in the IAM state.
 *
 * @param state [in]     The IAM state,
 * @param password [in]  The password which clients needs to specify to pair with the system. The string is copied into the module. Password pairing can be disabled with the NULL password.
 * @return false iff the password was not set
 */
bool nm_iam_state_set_password_open_password(struct nm_iam_state* state, const char* password);

/**
 * Set remote pairing server connect token in the IAM state. A client
 * cannot make a remote pairing unless it has a valid server connect
 * token. This sets that server connect token when the state is
 * loaded.
 *
 * @param state [in]               The IAM state
 * @param sct [in]  The server connect token the client needs to use when pairing remotely with the system. The string is copied into the system.
 * @return false iff the server connect token was not set
 */
bool nm_iam_state_set_password_open_sct(struct nm_iam_state* state, const char* sct);

/**
 * Enable/disable pairing modes. Each pairing mode will be disabled by
 * default if its corresponding set function is not called.
 *
 * @param state [in]  The IAM state
 * @param b [in]      The boolean value to set
 */
void nm_iam_state_set_password_open_pairing(struct nm_iam_state* state, bool b);
void nm_iam_state_set_local_open_pairing(struct nm_iam_state* state, bool b);
void nm_iam_state_set_password_invite_pairing(struct nm_iam_state* state, bool b);
void nm_iam_state_set_local_initial_pairing(struct nm_iam_state* state, bool b);

/**
 * Set the role to assign to new users paired through an open pairing
 * mode. The role ID string is copied into the state.
 *
 * @param state [in]            The IAM state
 * @param openPairingRole [in]  ID of the role to use.
 * @return true iff the role was set.
 */
bool nm_iam_state_set_open_pairing_role(struct nm_iam_state* state, const char* openPairingRole);

/**
 * Set the username to pair as during local initial pairing. The role
 * ID string is copied into the state.
 *
 * @param state [in]                   The IAM state
 * @param initialPairingUsername [in]  ID of the role to use.
 * @return true iff the username was set.
 */
bool nm_iam_state_set_initial_pairing_username(struct nm_iam_state* state, const char* initialPairingUsername);

/**
 * Add a user to the IAM state. The state takes ownership of the user
 * pointer.
 *
 * @param state [in]  State to add user to
 * @param user [in]   User to add
 * @return false iff the user could not be added
 */
bool nm_iam_state_add_user(struct nm_iam_state* state, struct nm_iam_user* user);


/****************
 * User Builder *
 ****************/

/**
 * Create a new user with the specified username. The username must
 * only use the character set: ['a-z', '0-9','_','-','.'].
 *
 * @param username [in]  The username. The string is copied into the user.
 * @return NULL iff the username was invalid or allocation failed
 */
struct nm_iam_user* nm_iam_state_user_new(const char* username);

/**
 * Free user created with nm_iam_state_user_new() if the ownership was
 * has not been transferred to the state using
 * nm_iam_state_add_user().
 *
 * @param user [in]  User to free
 */
void nm_iam_state_user_free(struct nm_iam_user* user);

/**
 * Set functions for modifying fingerprint, server connect token,
 * display name, role, and password in a user. Strings are copied into
 * the user when set.
 *
 * @param user [in]      User to set string in
 * @param <string> [in]  The string to copy into the user
 */
bool nm_iam_state_user_set_fingerprint(struct nm_iam_user* user, const char* fingerprint);
bool nm_iam_state_user_set_sct(struct nm_iam_user* user, const char* sct);
bool nm_iam_state_user_set_display_name(struct nm_iam_user* user, const char* displayName);
bool nm_iam_state_user_set_role(struct nm_iam_user* user, const char* roleId);
bool nm_iam_state_user_set_password(struct nm_iam_user* user, const char* password);

/**
 * Find a user with a given username in a state structure.
 *
 * @param state [in]     The state to look for the user in
 * @param username [in]  The username to look for
 * @return NULL iff the user could not be found
 */
struct nm_iam_user* nm_iam_state_find_user(struct nm_iam_state* state, const char* username);

/**
 * Copy a state object. The received copy must be freed with
 * nm_iam_state_free() or the ownership must be transferred to an IAM
 * module.
 *
 * @param state [in]  The state to copy
 * @return NULL iff the state could not be copied
 */
struct nm_iam_state* nm_iam_state_copy(struct nm_iam_state* state);

/**
 * Comomn helper functions
 */
struct nm_iam_user* nm_iam_state_find_user_by_username(struct nm_iam_state* state, const char* username);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
