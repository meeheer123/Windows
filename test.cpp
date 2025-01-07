#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <windows.h>
#include "NBioAPI.h"

void cleanup(NBioAPI_HANDLE handle, NBioAPI_FIR_HANDLE capturedFIR, NBioAPI_DEVICE_ID deviceID) {
    if (capturedFIR) {
        NBioAPI_FreeFIRHandle(handle, capturedFIR);
    }
    if (deviceID) {
        NBioAPI_CloseDevice(handle, deviceID);
    }
    if (handle) {
        NBioAPI_Terminate(handle);
    }
    std::cout << "Resources cleaned up successfully." << std::endl;
}

int main() {
    NBioAPI_HANDLE handle = 0;
    NBioAPI_FIR_HANDLE capturedFIR = 0;
    NBioAPI_DEVICE_ID deviceID = 0;
    NBioAPI_RETURN ret;

    std::cout << "Initializing the device..." << std::endl;

    // Initialize NBioAPI
    ret = NBioAPI_Init(&handle);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Failed to initialize: Error code " << ret << std::endl;
        return -1;
    }
    std::cout << "Device initialized successfully!" << std::endl;

    // Enumerate and open the first available device
    NBioAPI_UINT32 numDevices = 0;
    NBioAPI_DEVICE_ID* deviceList = nullptr;
    ret = NBioAPI_EnumerateDevice(handle, &numDevices, &deviceList);
    if (ret != NBioAPIERROR_NONE || numDevices == 0) {
        std::cerr << "No devices found! Error code: " << ret << std::endl;
        cleanup(handle, capturedFIR, deviceID);
        return -1;
    }
    deviceID = deviceList[0];
    ret = NBioAPI_OpenDevice(handle, deviceID);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Failed to open device! Error code: " << ret << std::endl;
        cleanup(handle, capturedFIR, deviceID);
        return -1;
    }

    // Set capture window options
    NBioAPI_WINDOW_OPTION windowOption = { 0 };
    windowOption.Length = sizeof(NBioAPI_WINDOW_OPTION);
    windowOption.WindowStyle = NBioAPI_WINDOW_STYLE_INVISIBLE;

    // Capture fingerprint
    ret = NBioAPI_Capture(handle, NBioAPI_FIR_PURPOSE_VERIFY, &capturedFIR, 5000, nullptr, &windowOption);
    if (ret != NBioAPIERROR_NONE || capturedFIR == 0) {
        std::cerr << "Failed to capture fingerprint. Error code: " << ret << std::endl;
        cleanup(handle, capturedFIR, deviceID);
        return -1;
    }
    std::cout << "Fingerprint captured successfully!" << std::endl;

    // Retrieve FIR
    NBioAPI_FIR fir;
    ret = NBioAPI_GetFIRFromHandle(handle, capturedFIR, &fir);
    if (ret != NBioAPIERROR_NONE || fir.Data == nullptr) {
        std::cerr << "Failed to retrieve FIR. Error code: " << ret << std::endl;
        cleanup(handle, capturedFIR, deviceID);
        return -1;
    }

    // Save FIR data
    time_t now = time(nullptr);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
    std::string filename = "fingerprint.fir";

    std::ofstream outFile(filename, std::ios::binary);
    if (outFile.is_open()) {
        DWORD firLength = sizeof(fir.Format) + fir.Header.Length + fir.Header.DataLength;
        BYTE* binaryStream = new BYTE[firLength];

        memcpy(binaryStream, &fir.Format, sizeof(fir.Format));
        memcpy(binaryStream + sizeof(fir.Format), &fir.Header, fir.Header.Length);
        memcpy(binaryStream + sizeof(fir.Format) + fir.Header.Length, fir.Data, fir.Header.DataLength);

        outFile.write(reinterpret_cast<char*>(binaryStream), firLength);
        outFile.close();
        delete[] binaryStream;

        std::cout << "Fingerprint data saved to " << filename << std::endl;
    } else {
        std::cerr << "Failed to save fingerprint data to file!" << std::endl;
    }

    // Cleanup and exit
    cleanup(handle, capturedFIR, deviceID);

    std::cout << "Program completed. Exiting now..." << std::endl;
    return 0;
}
