#include <fstream>
#include <stdexcept>
#include "NBioAPI.h"

// Function to load an FIR from a file
NBioAPI_RETURN LoadFIRFromFile(const std::string& filePath, NBioAPI_FIR& fir) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open FIR file.");
    }

    // Read FIR format
    file.read(reinterpret_cast<char*>(&fir.Format), sizeof(fir.Format));

    // Read FIR header
    file.read(reinterpret_cast<char*>(&fir.Header), sizeof(fir.Header));

    // Allocate memory for FIR data
    fir.Data = new NBioAPI_UINT8[fir.Header.DataLength];
    if (!fir.Data) {
        throw std::runtime_error("Failed to allocate memory for FIR data.");
    }

    // Read FIR data
    file.read(reinterpret_cast<char*>(fir.Data), fir.Header.DataLength);
    file.close();

    return NBioAPIERROR_NONE;
}

// Function to free FIR memory
void FreeFIR(NBioAPI_FIR& fir) {
    delete[] fir.Data;
    fir.Data = nullptr;
}

int main() {
    NBioAPI_RETURN ret;
    NBioAPI_HANDLE g_hBSP = 0;
    NBioAPI_FIR_HANDLE capturedFIR = 0;
    NBioAPI_DEVICE_ID deviceID = NBioAPI_DEVICE_ID_AUTO;
    NBioAPI_FIR existingFIR, capturedFIRData;
    NBioAPI_BOOL matchResult = NBioAPI_FALSE;
    NBioAPI_INPUT_FIR inputFIRStored, inputFIRCaptured;

    try {
        // Initialize the SDK
        ret = NBioAPI_Init(&g_hBSP);
        if (ret != NBioAPIERROR_NONE) {
            return -1; // Fail silently
        }

        // Load existing FIR from file
        LoadFIRFromFile("fingerprint_20250107_154117.fir", existingFIR);

        // Open fingerprint device
        ret = NBioAPI_OpenDevice(g_hBSP, deviceID);
        if (ret != NBioAPIERROR_NONE) {
            return -1; // Fail silently
        }

        // Capture a new fingerprint
        ret = NBioAPI_Capture(g_hBSP, NBioAPI_FIR_PURPOSE_VERIFY, &capturedFIR, 10000, nullptr, nullptr);
        if (ret != NBioAPIERROR_NONE) {
            return -1; // Fail silently
        }

        // Retrieve FIR data from captured handle
        ret = NBioAPI_GetFIRFromHandle(g_hBSP, capturedFIR, &capturedFIRData);
        if (ret != NBioAPIERROR_NONE) {
            return -1; // Fail silently
        }

        // Prepare inputs for matching
        inputFIRStored.Form = NBioAPI_FIR_FORM_FULLFIR;
        inputFIRStored.InputFIR.FIR = &existingFIR;

        inputFIRCaptured.Form = NBioAPI_FIR_FORM_FULLFIR;
        inputFIRCaptured.InputFIR.FIR = &capturedFIRData;

        // Perform matching
        ret = NBioAPI_VerifyMatch(g_hBSP, &inputFIRStored, &inputFIRCaptured, &matchResult, nullptr);
        if (ret == NBioAPIERROR_NONE) {
            // Log result to a file
            std::ofstream logFile("fingerprint_log.txt", std::ios::app);
            if (logFile.is_open()) {
                if (matchResult == NBioAPI_TRUE) {
                    logFile << "Fingerprint matched successfully!\n";
                } else {
                    logFile << "Fingerprint did not match.\n";
                }
                logFile.close();
            }
        }

        // Free FIR resources
        FreeFIR(existingFIR);
        NBioAPI_FreeFIR(g_hBSP, &capturedFIRData);

        // Close application immediately after completion
        NBioAPI_CloseDevice(g_hBSP, deviceID);
        NBioAPI_Terminate(g_hBSP);

        return 0;  // Exit silently
    } catch (...) {
        // General error handler: fail silently
        return -1;
    }
}
