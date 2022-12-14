/*
 * Copyright (c) 2022, Denis Bodor <lefinnois@lefinnois.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include "statusres.h"

// https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/

const char *
strstatus(uint16_t code) {
	switch(code) {
	case 0x6200: return("No information given (NV-Ram not changed)");
	case 0x6201: return("NV-Ram not changed 1");
	case 0x6281: return("Part of returned data may be corrupted");
	case 0x6282: return("End of file/record reached before reading Le bytes");
	case 0x6283: return("Selected file invalidated");
	case 0x6284: return("Selected file is not valid. FCI not formated according to ISO");
	case 0x6285: return("No input data available from a sensor on the card");
	case 0x62A2: return("Wrong R-MAC");
	case 0x62A4: return("Card locked (during reset())");
	case 0x62F1: return("Wrong C-MAC");
	case 0x62F3: return("Internal reset");
	case 0x62F5: return("Default agent locked");
	case 0x62F7: return("Cardholder locked");
	case 0x62F8: return("Basement is current agent");
	case 0x62F9: return("CALC Key Set not unblocked");
	case 0x6300: return("No information given (NV-Ram changed)");
	case 0x6381: return("File filled up by the last write. Loading/updating is not allowed");
	case 0x6382: return("Card key not supported");
	case 0x6383: return("Reader key not supported");
	case 0x6384: return("Plaintext transmission not supported");
	case 0x6385: return("Secured transmission not supported");
	case 0x6386: return("Volatile memory is not available");
	case 0x6387: return("Non-volatile memory is not available");
	case 0x6388: return("Key number not valid");
	case 0x6389: return("Key length is not correct");
	case 0x63C0: return("Verify fail, no try left");
	case 0x63C1: return("Verify fail, 1 try left");
	case 0x63C2: return("Verify fail, 2 tries left");
	case 0x63C3: return("Verify fail, 3 tries left");
	case 0x63F1: return("More data expected");
	case 0x63F2: return("More data expected and proactive command pending");
	case 0x6400: return("No information given (NV-Ram not changed)");
	case 0x6401: return("Command timeout. Immediate response required by the card");
	case 0x6500: return("No information given");
	case 0x6501: return("Write error. Memory failure. There have been problems in writing or reading the EEPROM");
	case 0x6581: return("Memory failure");
	case 0x6600: return("Error while receiving (timeout)");
	case 0x6601: return("Error while receiving (character parity error)");
	case 0x6602: return("Wrong checksum");
	case 0x6603: return("The current DF file without FCI");
	case 0x6604: return("No SF or KF under the current DF");
	case 0x6669: return("Incorrect Encryption/Decryption Padding");
	case 0x6700: return("Wrong length");
	case 0x6800: return("No information given (The request function is not supported by the card)");
	case 0x6881: return("Logical channel not supported");
	case 0x6882: return("Secure messaging not supported");
	case 0x6883: return("Last command of the chain expected");
	case 0x6884: return("Command chaining not supported");
	case 0x6900: return("No information given (Command not allowed)");
	case 0x6901: return("Command not accepted (inactive state)");
	case 0x6981: return("Command incompatible with file structure");
	case 0x6982: return("Security condition not satisfied");
	case 0x6983: return("Authentication method blocked");
	case 0x6984: return("Referenced data reversibly blocked (invalidated)");
	case 0x6985: return("Conditions of use not satisfied");
	case 0x6986: return("Command not allowed (no current EF)");
	case 0x6987: return("Expected secure messaging (SM) object missing");
	case 0x6988: return("Incorrect secure messaging (SM) data object");
	case 0x698D: return("Reserved");
	case 0x6996: return("Data must be updated again");
	case 0x69E1: return("POL1 of the currently Enabled Profile prevents this action");
	case 0x69F0: return("Permission Denied");
	case 0x69F1: return("Permission Denied ??? Missing Privilege");
	case 0x6A00: return("No information given (Bytes P1 and/or P2 are incorrect)");
	case 0x6A80: return("The parameters in the data field are incorrect");
	case 0x6A81: return("Function not supported");
	case 0x6A82: return("File not found");
	case 0x6A83: return("Record not found");
	case 0x6A84: return("There is insufficient memory space in record or file");
	case 0x6A85: return("Lc inconsistent with TLV structure");
	case 0x6A86: return("Incorrect P1 or P2 parameter");
	case 0x6A87: return("Lc inconsistent with P1-P2");
	case 0x6A88: return("Referenced data not found");
	case 0x6A89: return("File already exists");
	case 0x6A8A: return("DF name already exists");
	case 0x6AF0: return("Wrong parameter value");
	case 0x6B00: return("Wrong parameter(s) P1-P2");
	case 0x6C00: return("Incorrect P3 length");
	case 0x6D00: return("Instruction code not supported or invalid");
	case 0x6E00: return("Class not supported");
	case 0x6F00: return("Command aborted ??? more exact diagnosis not possible (e.g., operating system error)");
	case 0x6FFF: return("Card dead (overuse, ???)");
	case 0x9000: return("I Command successfully executed (OK)");
	case 0x9004: return("PIN not succesfully verified, 3 or more PIN tries left");
	case 0x9008: return("Key/file not found");
	case 0x9080: return("Unblock Try Counter has reached zero");
	case 0x9100: return("OK");
	case 0x9101: return("States.activity, States.lock Status or States.lockable has wrong value");
	case 0x9102: return("Transaction number reached its limit");
	case 0x910C: return("No changes");
	case 0x910E: return("Insufficient NV-Memory to complete command");
	case 0x911C: return("Command code not supported");
	case 0x911E: return("CRC or MAC does not match data");
	case 0x9140: return("Invalid key number specified");
	case 0x917E: return("Length of command string invalid");
	case 0x919D: return("Not allow the requested command");
	case 0x919E: return("Value of the parameter invalid");
	case 0x91A0: return("Requested AID not present on PICC");
	case 0x91A1: return("Unrecoverable error within application");
	case 0x91AE: return("Authentication status does not allow the requested command");
	case 0x91AF: return("Additional data frame is expected to be sent");
	case 0x91BE: return("Out of boundary");
	case 0x91C1: return("Unrecoverable error within PICC");
	case 0x91CA: return("Previous Command was not fully completed");
	case 0x91CD: return("PICC was disabled by an unrecoverable error");
	case 0x91CE: return("Number of Applications limited to 28");
	case 0x91DE: return("File or application already exists");
	case 0x91EE: return("Could not complete NV-write operation due to loss of power");
	case 0x91F0: return("Specified file number does not exist");
	case 0x91F1: return("Unrecoverable error within file");
	case 0x9210: return("Insufficient memory. No more storage available");
	case 0x9240: return("Writing to EEPROM not successful");
	case 0x9301: return("Integrity error");
	case 0x9302: return("Candidate S2 invalid");
	case 0x9303: return("Application is permanently locked");
	case 0x9400: return("No EF selected");
	case 0x9401: return("Candidate currency code does not match purse currency");
	case 0x9402: return("Address range exceeded / Candidate amount too high");
	case 0x9403: return("Candidate amount too low");
	case 0x9404: return("FID not found, record not found or comparison pattern not found");
	case 0x9405: return("Problems in the data field");
	case 0x9406: return("Required MAC unavailable");
	case 0x9407: return("Bad currency : purse engine has no slot with R3bc currency");
	case 0x9408: return("Selected file type does not match command / R3bc currency not supported in purse engine");
	case 0x9580: return("Bad sequence");
	case 0x9681: return("Slave not found");
	case 0x9700: return("PIN blocked and Unblock Try Counter is 1 or 2");
	case 0x9702: return("Main keys are blocked");
	case 0x9704: return("PIN not succesfully verified, 3 or more PIN tries left");
	case 0x9784: return("Base key");
	case 0x9785: return("Limit exceeded ??? C-MAC key");
	case 0x9786: return("SM error ??? Limit exceeded ??? R-MAC key");
	case 0x9787: return("Limit exceeded ??? sequence counter");
	case 0x9788: return("Limit exceeded ??? R-MAC length");
	case 0x9789: return("Service not available");
	case 0x9802: return("No PIN defined");
	case 0x9804: return("Access conditions not satisfied, authentication failed");
	case 0x9835: return("ASK RANDOM or GIVE RANDOM not executed");
	case 0x9840: return("PIN verification not successful");
	case 0x9850: return("INCREASE or DECREASE could not be executed because a limit has been reached");
	case 0x9862: return("Authentication Error, application specific (incorrect MAC)");
	case 0x9900: return("1 PIN try left");
	case 0x9904: return("PIN not succesfully verified, 1 PIN try left");
	case 0x9985: return("Wrong status ??? Cardholder lock");
	case 0x9986: return("Missing privilege");
	case 0x9987: return("PIN is not installed");
	case 0x9988: return("Wrong status ??? R-MAC state");
	case 0x9A00: return("2 PIN try left");
	case 0x9A04: return("PIN not succesfully verified, 2 PIN try left");
	case 0x9A71: return("Wrong parameter value ??? Double agent AID");
	case 0x9A72: return("Wrong parameter value ??? Double agent Type");
	case 0x9D05: return("Incorrect certificate type");
	case 0x9D07: return("Incorrect session data size");
	case 0x9D08: return("Incorrect DIR file record size");
	case 0x9D09: return("Incorrect FCI record size");
	case 0x9D0A: return("Incorrect code size");
	case 0x9D10: return("Insufficient memory to load application");
	case 0x9D11: return("Invalid AID");
	case 0x9D12: return("Duplicate AID");
	case 0x9D13: return("Application previously loaded");
	case 0x9D14: return("Application history list full");
	case 0x9D15: return("Application not open");
	case 0x9D17: return("Invalid offset");
	case 0x9D18: return("Application already loaded");
	case 0x9D19: return("Invalid certificate");
	case 0x9D1A: return("Invalid signature");
	case 0x9D1B: return("Invalid KTU");
	case 0x9D1D: return("MSM controls not set");
	case 0x9D1E: return("Application signature does not exist");
	case 0x9D1F: return("KTU does not exist");
	case 0x9D20: return("Application not loaded");
	case 0x9D21: return("Invalid Open command data length");
	case 0x9D30: return("Check data parameter is incorrect (invalid start address)");
	case 0x9D31: return("Check data parameter is incorrect (invalid length)");
	case 0x9D32: return("Check data parameter is incorrect (illegal memory check area)");
	case 0x9D40: return("Invalid MSM Controls ciphertext");
	case 0x9D41: return("MSM controls already set");
	case 0x9D42: return("Set MSM Controls data length less than 2 bytes");
	case 0x9D43: return("Invalid MSM Controls data length");
	case 0x9D44: return("Excess MSM Controls ciphertext");
	case 0x9D45: return("Verification of MSM Controls data failed");
	case 0x9D50: return("Invalid MCD Issuer production ID");
	case 0x9D51: return("Invalid MCD Issuer ID");
	case 0x9D52: return("Invalid set MSM controls data date");
	case 0x9D53: return("Invalid MCD number");
	case 0x9D54: return("Reserved field error");
	case 0x9D55: return("Reserved field error");
	case 0x9D56: return("Reserved field error");
	case 0x9D57: return("Reserved field error");
	case 0x9D60: return("MAC verification failed");
	case 0x9D61: return("Maximum number of unblocks reached");
	case 0x9D62: return("Card was not blocked");
	case 0x9D63: return("Crypto functions not available");
	case 0x9D64: return("No application loaded");
	case 0x9E00: return("PIN not installed");
	case 0x9E04: return("PIN not succesfully verified, PIN not installed");
	case 0x9F00: return("PIN blocked and Unblock Try Counter is 3");
	case 0x9F04: return("PIN not succesfully verified, PIN blocked and Unblock Try Counter is 3");
	default: return("Unknown error");
	}
}
