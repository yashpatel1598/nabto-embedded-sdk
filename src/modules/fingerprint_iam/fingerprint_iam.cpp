#include "fingerprint_iam.hpp"
#include "subject.hpp"

#include "coap_is_paired.hpp"
#include "coap_pairing.hpp"
#include "coap_pairing_password.hpp"
#include "coap_pairing_button.hpp"
#include "coap_client_settings.hpp"
#include "user_builder.hpp"
#include "fingerprint_iam_json.hpp"
#include "authorization_request_handler.hpp"


#include <modules/iam_cpp/decision.hpp>
#include <modules/iam_cpp/iam_to_json.hpp>

#include <cbor.h>
#include <iostream>

namespace nabto {
namespace fingerprint_iam {

FingerprintIAM::~FingerprintIAM()
{
}

FingerprintIAM::FingerprintIAM(NabtoDevice* device, FingerprintIAMPersisting& persisting)
    : device_(device), persisting_(persisting)
{
    coapIsPaired_ = CoapIsPaired::create(*this, device_);
    coapPairing_ = CoapPairing::create(*this, device_);

    authorizationRequestHandler_ = AuthorizationRequestHandler::create(device, *this);
}

void FingerprintIAM::enableButtonPairing(std::function<void (std::string fingerprint, std::function<void (bool accepted)> cb)> callback)
{
    coapPairingButton_ = std::make_unique<CoapPairingButton>(*this, device_);
    coapPairingButton_->init(callback);
}

void FingerprintIAM::enablePasswordPairing(const std::string& password)
{
    coapPairingPassword_ = std::make_unique<CoapPairingPassword>(*this, device_);
    coapPairingPassword_->init(password);
}

void FingerprintIAM::enableClientSettings(const std::string& clientServerUrl, const std::string& clientServerKey)
{
    coapClientSettings_ =  CoapClientSettings::create(*this, device_, clientServerUrl, clientServerKey);

}


bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action)
{
    nabto::iam::Attributes attributes;
    return checkAccess(ref, action, attributes);
}

static std::string verdictToString(bool verdict)
{
    return verdict ? "granted" : "denied";
}

bool FingerprintIAM::checkAccess(NabtoDeviceConnectionRef ref, const std::string& action, const nabto::iam::Attributes& attributes)
{
    NabtoDeviceError ec;
    char* fingerprint;
    ec = nabto_device_connection_get_client_fingerprint_hex(getDevice(), ref, &fingerprint);
    if (ec) {
        return false;
    }

    std::string clientFingerprint(fingerprint);
    nabto_device_string_free(fingerprint);

    std::shared_ptr<User> user = findUserByFingerprint(clientFingerprint);
    bool verdict;
    if (user) {
        auto subject = createSubjectFromUser(*user);
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);

        std::cout << "Access " << verdictToString(verdict) << " to the action: " << action << " for the user: " << user->getId() << " on the connection: " << ref << std::endl;
    } else {
        auto subject = createUnpairedSubject();
        verdict = nabto::iam::Decision::checkAccess(subject, action, attributes);
        std::cout << "Access " << verdictToString(verdict) << " to the action: " << action << " for the unpaired connection: " << ref << " with the role: 'Unpaired'" << std::endl;
    }

    return verdict;
}

void FingerprintIAM::addPolicy(const nabto::iam::Policy& policy)
{
    policies_[policy.getId()] = std::make_shared<nabto::iam::Policy>(policy);
}


bool FingerprintIAM::addRole(const iam::RoleBuilder& roleBuilder)
{
    if (roles_.find(roleBuilder.getId()) != roles_.end()) {
        return false;
    }
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto policyString : roleBuilder.getPolicies()) {
        auto it = policies_.find(policyString);
        if (it != policies_.end()) {
            policies.insert(it->second);
        } else {
            return false;
        }
    }
    roles_[roleBuilder.getId()] = std::make_shared<Role>(roleBuilder.getId(), policies);
    return true;
}

bool FingerprintIAM::addUser(const UserBuilder& ub)
{
    if (users_.find(ub.getId()) != users_.end()) {
        return false;
    }

    std::set<std::shared_ptr<Role> > roles;
    for (auto roleString : ub.getRoles()) {
        auto it = roles_.find(roleString);
        if (it != roles_.end()) {
            roles.insert(it->second);
        } else {
            return false;
        }
    }

    insertUser(std::make_shared<User>(ub.getId(), roles, ub.getFingerprints(), ub.getAttributes()));
    return true;
}

std::vector<std::string> FingerprintIAM::getPairingModes()
{
    std::vector<std::string> modes;
    if (coapPairingPassword_) {
        modes.push_back("Password");
    }
    if (coapPairingButton_) {
        modes.push_back("Button");
    }
    return modes;
}

void FingerprintIAM::dumpUsers()
{
    std::cout << "IAM Users. User Count " << users_.size() << std::endl;
    for (auto u : users_) {
        std::cout << FingerprintIAMJson::userToJson(*u.second) << std::endl;
    }
}

void FingerprintIAM::dumpRoles()
{
    std::cout << "IAM Roles. Role Count " << roles_.size() << std::endl;
    for (auto r : roles_) {
        std::cout << FingerprintIAMJson::roleToJson(*r.second) << std::endl;
    }
}

void FingerprintIAM::dumpPolicies()
{
    std::cout << "IAM Policies. Policies Count " << policies_.size() << std::endl;
    for (auto p : policies_) {
        std::cout << iam::IAMToJson::policyToJson(*p.second) << std::endl;
    }
}

std::string FingerprintIAM::nextUserId()
{
   std::stringstream ss;
   ss << "" << users_.size()+1;
   return ss.str();
}

bool FingerprintIAM::pairNewClient(const std::string& fingerprint)
{
    {
        auto user = findUserByFingerprint(fingerprint);
        if (user) {
            // user is already paired.
            return true;
        }
    }

    std::shared_ptr<Role> role;
    if (users_.size() == 0) {
        role = getRole("Admin");
        if (role == nullptr) {
            std::cout << "Warning missing the Role 'Admin' cannot pair the user" << std::endl;
            return false;
        }
    } else {
        role = getRole("User");
        if (role == nullptr) {
            std::cout << "Warning missing the Role 'User' cannot pair the user" << std::endl;
            return false;
        }
    }
    auto user = std::make_shared<User>(nextUserId(), role);
    insertUser(user);
    addFingerprintToUser(user, fingerprint);
    return true;
}


std::shared_ptr<User> FingerprintIAM::findUserByFingerprint(const std::string& fingerprint)
{
    auto it = fingerprintToUser_.find(fingerprint);
    if (it != fingerprintToUser_.end()) {
        return it->second;
    }
    return nullptr;
}


Subject FingerprintIAM::createUnpairedSubject()
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    auto unpairedRole_ = getRole("Unpaired");
    if (unpairedRole_) {
        for (auto policy : unpairedRole_->getPolicies()) {
            policies.insert(policy);
        }
    } else {
        std::cout << "No role 'Unpaired' in the system, the user has no access rights." << std::endl;
    }
    nabto::iam::Attributes attributes;
    return Subject(policies, attributes);
}

Subject FingerprintIAM::createSubjectFromUser(const User& user)
{
    std::set<std::shared_ptr<nabto::iam::Policy> > policies;
    for (auto role : user.getRoles()) {
        for (auto policy : role->getPolicies()) {
            policies.insert(policy);
        }
    }
    return Subject(policies, user.getAttributes());
}

void FingerprintIAM::insertUser(std::shared_ptr<User> user)
{
    users_[user->getId()] = user;
    for (auto fp : user->getFingerprints()) {
        fingerprintToUser_[fp] = user;
    }
    persisting_.upsertUser(*user);
}

} } // namespace
