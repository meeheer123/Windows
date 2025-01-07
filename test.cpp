#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <windows.h>
#include "NBioAPI.h"

int main() {
    NBioAPI_HANDLE handle = 0;
    NBioAPI_RETURN ret;

    std::cout << "Initializing device..." << std::endl;
    ret = NBioAPI_Init(&handle);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Error: Initialization failed. Code " << ret << std::endl;
        return -1;
    }

    NBioAPI_UINT32 numDevices;
    NBioAPI_DEVICE_ID* deviceList = nullptr;
    ret = NBioAPI_EnumerateDevice(handle, &numDevices, &deviceList);
    if (ret != NBioAPIERROR_NONE || numDevices == 0) {
        std::cerr << "Error: No devices found. Code " << ret << std::endl;
        NBioAPI_Terminate(handle);
        return -1;
    }

    ret = NBioAPI_OpenDevice(handle, deviceList[0]);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Error: Failed to open device. Code " << ret << std::endl;
        NBioAPI_Terminate(handle);
        return -1;
    }

    NBioAPI_WINDOW_OPTION windowOption = { 0 };
    windowOption.Length = sizeof(NBioAPI_WINDOW_OPTION);
    windowOption.WindowStyle = NBioAPI_WINDOW_STYLE_INVISIBLE;

    NBioAPI_FIR_HANDLE capturedFIR = 0;
    ret = NBioAPI_Capture(handle, NBioAPI_FIR_PURPOSE_VERIFY, &capturedFIR, 5000, nullptr, &windowOption);

    if (ret != NBioAPIERROR_NONE || capturedFIR == 0) {
        std::cerr << "Error: Capture failed. Code " << ret << std::endl;
        NBioAPI_CloseDevice(handle, deviceList[0]);
        NBioAPI_Terminate(handle);
        return -1;
    }

    std::cout << "Capture successful!" << std::endl;

    time_t now = time(nullptr);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
    std::string filename = "fingerprint_" + std::string(timestamp) + ".fir";

    std::ofstream outFile(filename, std::ios::binary);
    if (outFile.is_open()) {
        outFile << "Dummy fingerprint data"; // Replace with actual fingerprint data
        outFile.close();
        std::cout << "Fingerprint data saved to " << filename << std::endl;
    } else {
        std::cerr << "Error: Failed to save fingerprint data!" << std::endl;
    }

    NBioAPI_FreeFIRHandle(handle, capturedFIR);
    NBioAPI_CloseDevice(handle, deviceList[0]);
    NBioAPI_Terminate(handle);

    return 0;
}
