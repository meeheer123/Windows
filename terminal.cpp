#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <windows.h>
#include "NBioAPI.h"

int main() {
    NBioAPI_HANDLE handle = 0;
    NBioAPI_RETURN ret;

    std::cout << "Initializing the device..." << std::endl;

    // Initialize the device
    ret = NBioAPI_Init(&handle);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Failed to initialize: Error code " << ret << std::endl;
        system("pause");
        return -1;
    }
    std::cout << "Device initialized successfully!" << std::endl;

    // Open the first available device
    NBioAPI_UINT32 numDevices;
    NBioAPI_DEVICE_ID* deviceList = nullptr;
    ret = NBioAPI_EnumerateDevice(handle, &numDevices, &deviceList);
    if (ret != NBioAPIERROR_NONE || numDevices == 0) {
        std::cerr << "No devices found! Error code: " << ret << std::endl;
        NBioAPI_Terminate(handle);
        system("pause");
        return -1;
    }
    ret = NBioAPI_OpenDevice(handle, deviceList[0]);
    if (ret != NBioAPIERROR_NONE) {
        std::cerr << "Failed to open device! Error code: " << ret << std::endl;
        NBioAPI_Terminate(handle);
        system("pause");
        return -1;
    }

    // Set up window options (invisible)
    NBioAPI_WINDOW_OPTION windowOption = { 0 };
    windowOption.Length = sizeof(NBioAPI_WINDOW_OPTION);
    windowOption.WindowStyle = NBioAPI_WINDOW_STYLE_INVISIBLE;

    // Capture fingerprint
    NBioAPI_FIR_HANDLE capturedFIR = 0;
    ret = NBioAPI_Capture(
        handle,
        NBioAPI_FIR_PURPOSE_VERIFY,
        &capturedFIR,
        5000,  // Timeout: 5 seconds
        nullptr,
        &windowOption
    );

    if (ret != NBioAPIERROR_NONE || capturedFIR == 0) {
        std::cerr << "Failed to capture fingerprint. Error code: " << ret << std::endl;
        NBioAPI_CloseDevice(handle, deviceList[0]);
        NBioAPI_Terminate(handle);
        return -1;
    }
    std::cout << "Fingerprint captured successfully!" << std::endl;

    // Retrieve FIR data
    NBioAPI_FIR fir;
    ret = NBioAPI_GetFIRFromHandle(handle, capturedFIR, &fir);
    if (ret != NBioAPIERROR_NONE || fir.Data == nullptr) {
        std::cerr << "Failed to retrieve FIR. Error code: " << ret << std::endl;
        NBioAPI_FreeFIRHandle(handle, capturedFIR);
        NBioAPI_CloseDevice(handle, deviceList[0]);
        NBioAPI_Terminate(handle);
        return -1;
    }

    // Validate and save FIR
    DWORD firLength = sizeof(fir.Format) + fir.Header.Length + fir.Header.DataLength;
    if (fir.Header.DataLength != firLength - sizeof(fir.Format) - fir.Header.Length) {
        std::cerr << "Data length mismatch! Header: " << fir.Header.DataLength
                  << ", Actual: " << firLength - sizeof(fir.Format) - fir.Header.Length << std::endl;
    } else {
        // Save FIR to file
        time_t now = time(nullptr);
        char timestamp[20];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
        std::string filename = "fingerprint_" + std::string(timestamp) + ".fir";

        std::ofstream outFile(filename, std::ios::binary);
        if (outFile.is_open()) {
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
    }

    // Cleanup
    NBioAPI_FreeFIR(handle, &fir);
    NBioAPI_FreeFIRHandle(handle, capturedFIR);
    NBioAPI_CloseDevice(handle, deviceList[0]);
    NBioAPI_Terminate(handle);

    std::cout << "Done! Press any key to exit..." << std::endl;
    system("pause");
    return 0;
}
