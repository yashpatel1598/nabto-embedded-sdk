#include "nm_iam_from_json.h"

#include "nm_iam_role.h"
#include "nm_iam_user.h"

#include <string.h>

struct nm_iam_role* nm_iam_role_from_json(const cJSON* json)
{
    cJSON* id = cJSON_GetObjectItem(json, "Id");
    cJSON* policies = cJSON_GetObjectItem(json, "Policies");

    if (!cJSON_IsString(id) ||
        !cJSON_IsArray(policies))
    {
        return NULL;
    }

    struct nm_iam_role* role = nm_iam_role_new(id->valuestring);
    size_t policiesSize = cJSON_GetArraySize(policies);
    for (size_t i = 0; i < policiesSize; i++) {
        cJSON* p = cJSON_GetArrayItem(policies, i);
        // todo handle non strings.
        if (cJSON_IsString(p)) {
            nn_string_set_insert(&role->policies, p->valuestring);
        }
    }
    return role;
}

struct nm_iam_user* nm_iam_user_from_json(const cJSON* json)
{
    cJSON* username = cJSON_GetObjectItem(json, "Username");
    cJSON* displayName = cJSON_GetObjectItem(json, "DisplayName");
    cJSON* serverConnectToken = cJSON_GetObjectItem(json, "ServerConnectToken");
    cJSON* fingerprint = cJSON_GetObjectItem(json, "Fingerprint");
    cJSON* password = cJSON_GetObjectItem(json, "Password");
    cJSON* role = cJSON_GetObjectItem(json, "Role");

    if (!cJSON_IsString(username)) {
        return NULL;
    }

    struct nm_iam_user* user = nm_iam_user_new(username->valuestring);
    if (user == NULL) {
        return NULL;
    }

    if (cJSON_IsString(displayName)) {
        nm_iam_user_set_display_name(user, displayName->valuestring);
    }

    if (cJSON_IsString(fingerprint)) {
        nm_iam_user_set_fingerprint(user, fingerprint->valuestring);
    }

    if (cJSON_IsString(password)) {
        nm_iam_user_set_password(user, password->valuestring);
    }

    if (cJSON_IsString(serverConnectToken)) {
        nm_iam_user_set_server_connect_token(user, serverConnectToken->valuestring);
    }

    if (cJSON_IsString(role)) {
        nm_iam_user_set_role(user, role->valuestring);
    }

    return user;
}
