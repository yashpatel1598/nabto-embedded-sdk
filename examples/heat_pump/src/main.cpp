#include "heat_pump.hpp"
#include "heat_pump_config.hpp"
#include "heat_pump_iam_policies.hpp"
#include "heat_pump_coap.hpp"

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void my_handler(int s){
           printf("Caught signal %d\n",s);
           exit(1);
}

bool init_heat_pump(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server);
void run_heat_pump(const std::string& configFile);

int main(int argc, char** argv) {
    cxxopts::Options options("Heat pump", "Nabto heat pump example.");

    options.add_options("General")
        ("h,help", "Show help")
        ("i,init", "Initialize configuration file")
        ("c,config", "Configuration file", cxxopts::value<std::string>()->default_value("heat_pump_device.json"))
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("info"))
        ("log-file", "File to log to", cxxopts::value<std::string>()->default_value("heat_pump_device_log.txt"));

    options.add_options("Init Parameters")
        ("p,product", "Product id", cxxopts::value<std::string>())
        ("d,device", "Device id", cxxopts::value<std::string>())
        ("s,server", "hostname of the server", cxxopts::value<std::string>());

    try {

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (result.count("init") > 0) {
            std::string configFile = result["config"].as<std::string>();
            std::string productId = result["product"].as<std::string>();
            std::string deviceId = result["device"].as<std::string>();
            std::string server = result["server"].as<std::string>();
            if (!init_heat_pump(configFile, productId, deviceId, server)) {
                std::cerr << "Initialization failed" << std::endl;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            run_heat_pump(configFile);
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    } catch (const std::domain_error& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    }
    return 0;
}

NabtoDeviceError load_policy(NabtoDevice* device, const std::string& name, json policy)
{
    auto cbor = json::to_cbor(policy);
    return nabto_device_iam_policy_create(device, name.c_str(), cbor.data(), cbor.size());
}

bool init_heat_pump(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
{
    if (heat_pump_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        exit(2);
    }

    json config;

    NabtoDevice* device = nabto_device_new();

    char* privateKey = nabto_device_experimental_util_create_private_key(device);
    config["PrivateKey"] = std::string(privateKey);
    config["ProductId"] = productId;
    config["DeviceId"] = deviceId;
    config["Server"] = server;

    if (nabto_device_iam_users_create(device, "Unpaired") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_set_default_user(device, "Unpaired") != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nabto_device_iam_users_create(device, OWNER_USER_NAME) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nabto_device_iam_roles_create(device, "FirstUser") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_users_add_role(device, "Unpaired", "FirstUser") != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nabto_device_iam_roles_create(device, "FullAccess") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_users_add_role(device, OWNER_USER_NAME, "FullAccess") != NABTO_DEVICE_EC_OK) {
        return false;
    }


    if (load_policy(device, "HeatPumpRead", HeatPumpRead) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "HeatPumpWrite", HeatPumpWrite) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "FirstUserCanPair", FirstUserCanPair) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "IAMFullAccess", IAMFullAccess) != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (load_policy(device, "ModifyOwnUser", IAMFullAccess) != NABTO_DEVICE_EC_OK) {
        return false;
    }



    if (nabto_device_iam_roles_add_policy(device, "FirstUser", "FirstUserCanPair") != NABTO_DEVICE_EC_OK) {
        return false;
    }

    if (nabto_device_iam_roles_add_policy(device, "FullAccess", "HeatPumpWrite") != NABTO_DEVICE_EC_OK) {
        return false;
    }
    if (nabto_device_iam_roles_add_policy(device, "FullAccess", "IAMFullAccess") != NABTO_DEVICE_EC_OK) {
        return false;
    }


    uint64_t version;
    size_t used;
    if (nabto_device_iam_dump(device, &version, NULL, 0, &used) != NABTO_DEVICE_EC_OUT_OF_MEMORY) {
        return false;
    }

    std::vector<uint8_t> buffer(used);
    if(nabto_device_iam_dump(device, &version, buffer.data(), buffer.size(), &used) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    config["Iam"] = json::from_cbor(buffer);


    std::string tmpFile = "tmp.json";
    heat_pump_save_config(configFile, tmpFile, config);

    nabto_device_free(device);

    return true;
}

void run_heat_pump(const std::string& configFile)
{
    NabtoDeviceError ec;
    json config;
    if (!heat_pump_load_config(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        exit(-1);
    }

    NabtoDevice* device = nabto_device_new();

    auto productId = config["ProductId"].get<std::string>();
    auto deviceId  = config["DeviceId"].get<std::string>();
    auto server = config["Server"].get<std::string>();
    auto privateKey = config["PrivateKey"].get<std::string>();
    auto iam = config["Iam"];

    nabto_device_set_product_id(device, productId.c_str());
    nabto_device_set_device_id(device, deviceId.c_str());
    nabto_device_set_server_url(device, server.c_str());
    nabto_device_set_private_key(device, privateKey.c_str());
    std::vector<uint8_t> iamCbor = json::to_cbor(iam);

    if (nabto_device_iam_load(device, iamCbor.data(), iamCbor.size()) != NABTO_DEVICE_EC_OK) {
        std::cerr << "failed to load iam" << std::endl;
    }
    nabto_device_enable_mdns(device);
    nabto_device_log_set_std_out_callback(device);

    // run application
    ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    char fp[33];
    memset(fp, 0, 33);
    nabto_device_get_device_fingerprint_hex(device, fp);

    std::cout << "Device " << productId << "." << deviceId << " Started with fingerprint " << std::string(fp) << std::endl;

    HeatPump hp(device, configFile);

    heat_pump_coap_init(device, &hp);

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    nabto_device_free(device);
    exit(0);
}
