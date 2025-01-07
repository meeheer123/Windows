#include <fstream>
#include <stdexcept>
#include "NBioAPI.h"
#include <iostream>
#include <ctime> // for time and date in log

// Function to load an FIR from a file
NBioAPI_RETURN LoadFIRFromFile(const std::string& filePath, NBioAPI_FIR& fir) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open FIR file: " + filePath);
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

// Function to log the result of the fingerprint verification
void LogResult(bool isMatch, const std::string& logFilePath) {
    std::ofstream logFile(logFilePath, std::ios::app); // Append mode
    if (logFile.is_open()) {
        // Get current time for logging timestamp
        std::time_t currentTime = std::time(nullptr);
        char timeBuffer[100];
        std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&currentTime));

        // Write the result to the log
        logFile << "[" << timeBuffer << "] Match result: " << (isMatch ? "Success" : "Failure") << std::endl;
        logFile.close();
    }
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
            LogResult(false, "fingerprint_verification_log.txt");
            return 1; // Failure
        }

        // Load the first FIR (fingerprint.fir)
        ret = LoadFIRFromFile("fingerprint.fir", existingFIR);
        if (ret != NBioAPIERROR_NONE) {
            NBioAPI_Terminate(g_hBSP);
            LogResult(false, "fingerprint_verification_log.txt");
            return 1; // Failure
        }

        // Load the second FIR (dataFingerprint.fir)
        ret = LoadFIRFromFile("dataFingerprint.fir", capturedFIRData);
        if (ret != NBioAPIERROR_NONE) {
            FreeFIR(existingFIR);
            NBioAPI_Terminate(g_hBSP);
            LogResult(false, "fingerprint_verification_log.txt");
            return 1; // Failure
        }

        // Prepare inputs for matching
        inputFIRStored.Form = NBioAPI_FIR_FORM_FULLFIR;
        inputFIRStored.InputFIR.FIR = &existingFIR;

        inputFIRCaptured.Form = NBioAPI_FIR_FORM_FULLFIR;
        inputFIRCaptured.InputFIR.FIR = &capturedFIRData;

        // Perform matching
        ret = NBioAPI_VerifyMatch(g_hBSP, &inputFIRStored, &inputFIRCaptured, &matchResult, nullptr);
        if (ret == NBioAPIERROR_NONE) {
            // Log the match result (Success or Failure)
            LogResult(matchResult == NBioAPI_TRUE, "fingerprint_verification_log.txt");

            if (matchResult == NBioAPI_TRUE) {
                return 0; // Match found
            } else {
                return 1; // No match found
            }
        } else {
            LogResult(false, "fingerprint_verification_log.txt");
            return 1; // Failure in verification
        }

        // Free FIR resources
        FreeFIR(existingFIR);
        FreeFIR(capturedFIRData);

        // Cleanup and terminate
        NBioAPI_Terminate(g_hBSP);

        return 1; // Unexpected case
    } catch (const std::exception& e) {
        FreeFIR(existingFIR);
        FreeFIR(capturedFIRData);
        NBioAPI_Terminate(g_hBSP);
        LogResult(false, "fingerprint_verification_log.txt");
        return 1; // Failure
    }
}
