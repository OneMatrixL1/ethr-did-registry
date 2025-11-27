/* SPDX-License-Identifier: MIT */

pragma solidity ^0.8.28;

/**
 * @title P256JWTVerifier
 * @notice Verifies JWT ES256 signatures using the secp256r1 (P-256) precompile
 * @dev Implements JWT signature verification with the RIP-7212 P-256 precompile at address 0x100
 */
contract P256JWTVerifier {
    // RIP-7212 P-256 signature verification precompile address
    address private constant P256_VERIFIER = address(0x100);
    
    // secp256r1 curve order (n)
    uint256 private constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    
    // Half of curve order for signature malleability check
    uint256 private constant P256_N_DIV_2 = P256_N / 2;

    error InvalidSignature();
    error MalleableSignature();
    error PrecompileCallFailed();
    error ArrayLengthMismatch();
    error InvalidJWTFormat();
    error InvalidBase64URL();
    error InvalidSignatureLength();

    /**
     * @notice Verifies a JWT ES256 signature
     * @param headerAndPayload The concatenated JWT header and payload (e.g., "eyJ...header.eyJ...payload")
     * @param r The r component of the ECDSA signature (32 bytes)
     * @param s The s component of the ECDSA signature (32 bytes)
     * @param publicKeyX The x-coordinate of the P-256 public key (32 bytes)
     * @param publicKeyY The y-coordinate of the P-256 public key (32 bytes)
     * @return True if the signature is valid, false otherwise
     */
    function verifyJWT(
        bytes calldata headerAndPayload,
        bytes32 r,
        bytes32 s,
        bytes32 publicKeyX,
        bytes32 publicKeyY
    ) external view returns (bool) {
        // Hash the message with SHA-256
        bytes32 messageHash = sha256(headerAndPayload);
        
        // Verify the signature using the precompile
        return verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY);
    }

    /**
     * @notice Low-level P-256 signature verification
     * @param messageHash The SHA-256 hash of the message (32 bytes)
     * @param r The r component of the ECDSA signature (32 bytes)
     * @param s The s component of the ECDSA signature (32 bytes)
     * @param publicKeyX The x-coordinate of the P-256 public key (32 bytes)
     * @param publicKeyY The y-coordinate of the P-256 public key (32 bytes)
     * @return True if the signature is valid, false otherwise
     */
    function verifyP256Signature(
        bytes32 messageHash,
        bytes32 r,
        bytes32 s,
        bytes32 publicKeyX,
        bytes32 publicKeyY
    ) public view returns (bool) {
        // Check for signature malleability (s must be in lower half)
        if (uint256(s) > P256_N_DIV_2) {
            revert MalleableSignature();
        }

        // Prepare input for precompile: hash || r || s || x || y (160 bytes total)
        bytes memory input = abi.encodePacked(
            messageHash,
            r,
            s,
            publicKeyX,
            publicKeyY
        );

        // Call the P-256 precompile
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(input);
        
        if (!success) {
            revert PrecompileCallFailed();
        }

        // Precompile returns 0x01 for valid signature, 0x00 for invalid
        bool isValid = result.length > 0 && uint8(result[0]) == 1;
        
        return isValid;
    }

    /**
     * @notice Parse and verify a complete JWT token (header.payload.signature)
     * @param jwt The complete JWT token as a string
     * @param publicKeyX The x-coordinate of the P-256 public key (32 bytes)
     * @param publicKeyY The y-coordinate of the P-256 public key (32 bytes)
     * @return True if the signature is valid, false otherwise
     */
    function verifyJWTComplete(
        string calldata jwt,
        bytes32 publicKeyX,
        bytes32 publicKeyY
    ) external view returns (bool) {
        // Parse JWT to extract components
        (bytes memory headerAndPayload, bytes32 r, bytes32 s) = parseJWT(jwt);
        
        // Hash the header.payload
        bytes32 messageHash = sha256(headerAndPayload);
        
        // Verify the signature
        return verifyP256Signature(messageHash, r, s, publicKeyX, publicKeyY);
    }

    /**
     * @notice Parse a JWT token to extract header.payload and signature components
     * @param jwt The complete JWT token string (header.payload.signature)
     * @return headerAndPayload The concatenated header.payload portion
     * @return r The r component of the signature (32 bytes)
     * @return s The s component of the signature (32 bytes)
     */
    function parseJWT(string calldata jwt) public pure returns (
        bytes memory headerAndPayload,
        bytes32 r,
        bytes32 s
    ) {
        bytes memory jwtBytes = bytes(jwt);
        
        // Find the positions of the two dots
        uint256 firstDot = 0;
        uint256 secondDot = 0;
        uint256 dotCount = 0;
        
        for (uint256 i = 0; i < jwtBytes.length; i++) {
            if (jwtBytes[i] == 0x2E) { // '.' character
                dotCount++;
                if (dotCount == 1) {
                    firstDot = i;
                } else if (dotCount == 2) {
                    secondDot = i;
                    break;
                }
            }
        }
        
        // JWT must have exactly 2 dots (3 parts)
        if (dotCount != 2 || firstDot == 0 || secondDot <= firstDot + 1) {
            revert InvalidJWTFormat();
        }
        
        // Extract header.payload (everything before second dot)
        headerAndPayload = new bytes(secondDot);
        for (uint256 i = 0; i < secondDot; i++) {
            headerAndPayload[i] = jwtBytes[i];
        }
        
        // Extract signature (everything after second dot)
        uint256 sigLength = jwtBytes.length - secondDot - 1;
        bytes memory signatureB64 = new bytes(sigLength);
        for (uint256 i = 0; i < sigLength; i++) {
            signatureB64[i] = jwtBytes[secondDot + 1 + i];
        }
        
        // Decode base64url signature
        bytes memory signature = base64URLDecode(signatureB64);
        
        // ES256 signature should be 64 bytes (32 bytes r + 32 bytes s)
        if (signature.length != 64) {
            revert InvalidSignatureLength();
        }
        
        // Extract r and s
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
        }
        
        return (headerAndPayload, r, s);
    }

    /**
     * @notice Decode a base64url encoded string
     * @param input The base64url encoded bytes
     * @return The decoded bytes
     */
    function base64URLDecode(bytes memory input) public pure returns (bytes memory) {
        // Base64URL to Base64: replace '-' with '+' and '_' with '/'
        for (uint256 i = 0; i < input.length; i++) {
            if (input[i] == 0x2D) { // '-'
                input[i] = 0x2B; // '+'
            } else if (input[i] == 0x5F) { // '_'
                input[i] = 0x2F; // '/'
            }
        }
        
        // Calculate output length (base64 decoding reduces by ~25%)
        uint256 inputLength = input.length;
        
        // Add padding if needed
        uint256 paddingCount = (4 - (inputLength % 4)) % 4;
        
        // Decode base64
        return base64Decode(input, paddingCount);
    }

    /**
     * @notice Internal base64 decoder
     * @param data The base64 encoded data
     * @param paddingCount Number of padding characters needed
     * @return The decoded bytes
     */
    function base64Decode(bytes memory data, uint256 paddingCount) internal pure returns (bytes memory) {
        uint256 inputLength = data.length;
        uint256 outputLength = ((inputLength + paddingCount) * 3) / 4 - paddingCount;
        
        bytes memory result = new bytes(outputLength);
        
        uint256 j = 0;
        for (uint256 i = 0; i < inputLength; i += 4) {
            uint256 a = base64CharValue(data[i]);
            uint256 b = i + 1 < inputLength ? base64CharValue(data[i + 1]) : 0;
            uint256 c = i + 2 < inputLength ? base64CharValue(data[i + 2]) : 0;
            uint256 d = i + 3 < inputLength ? base64CharValue(data[i + 3]) : 0;
            
            uint256 triple = (a << 18) | (b << 12) | (c << 6) | d;
            
            if (j < outputLength) result[j++] = bytes1(uint8(triple >> 16));
            if (j < outputLength) result[j++] = bytes1(uint8((triple >> 8) & 0xFF));
            if (j < outputLength) result[j++] = bytes1(uint8(triple & 0xFF));
        }
        
        return result;
    }

    /**
     * @notice Get the numeric value of a base64 character
     * @param char The base64 character
     * @return The numeric value (0-63)
     */
    function base64CharValue(bytes1 char) internal pure returns (uint256) {
        uint8 c = uint8(char);
        
        if (c >= 0x41 && c <= 0x5A) return c - 0x41; // A-Z: 0-25
        if (c >= 0x61 && c <= 0x7A) return c - 0x61 + 26; // a-z: 26-51
        if (c >= 0x30 && c <= 0x39) return c - 0x30 + 52; // 0-9: 52-61
        if (c == 0x2B) return 62; // '+': 62
        if (c == 0x2F) return 63; // '/': 63
        
        revert InvalidBase64URL();
    }

    /**
     * @notice Batch verify multiple JWT signatures with pre-extracted components
     * @param headerAndPayloads Array of JWT header.payload strings
     * @param rValues Array of r values
     * @param sValues Array of s values
     * @param publicKeysX Array of public key x-coordinates
     * @param publicKeysY Array of public key y-coordinates
     * @return results Array of boolean results for each verification
     */
    function batchVerifyJWT(
        bytes[] calldata headerAndPayloads,
        bytes32[] calldata rValues,
        bytes32[] calldata sValues,
        bytes32[] calldata publicKeysX,
        bytes32[] calldata publicKeysY
    ) external view returns (bool[] memory results) {
        if (
            headerAndPayloads.length != rValues.length ||
            rValues.length != sValues.length ||
            sValues.length != publicKeysX.length ||
            publicKeysX.length != publicKeysY.length
        ) {
            revert ArrayLengthMismatch();
        }

        results = new bool[](headerAndPayloads.length);

        for (uint256 i = 0; i < headerAndPayloads.length; i++) {
            bytes32 messageHash = sha256(headerAndPayloads[i]);
            
            // Skip malleability check in batch mode, return false instead of reverting
            if (uint256(sValues[i]) > P256_N_DIV_2) {
                results[i] = false;
                continue;
            }

            bytes memory input = abi.encodePacked(
                messageHash,
                rValues[i],
                sValues[i],
                publicKeysX[i],
                publicKeysY[i]
            );

            (bool success, bytes memory result) = P256_VERIFIER.staticcall(input);
            
            results[i] = success && result.length > 0 && uint8(result[0]) == 1;
        }

        return results;
    }

    /**
     * @notice Batch verify complete JWT tokens - parses and verifies on-chain
     * @param jwts Array of complete JWT token strings (header.payload.signature)
     * @param publicKeysX Array of public key x-coordinates
     * @param publicKeysY Array of public key y-coordinates
     * @return results Array of boolean results for each verification
     */
    function batchVerifyJWTComplete(
        string[] calldata jwts,
        bytes32[] calldata publicKeysX,
        bytes32[] calldata publicKeysY
    ) external view returns (bool[] memory results) {
        if (
            jwts.length != publicKeysX.length ||
            publicKeysX.length != publicKeysY.length
        ) {
            revert ArrayLengthMismatch();
        }

        results = new bool[](jwts.length);

        for (uint256 i = 0; i < jwts.length; i++) {
            try this.parseJWT(jwts[i]) returns (
                bytes memory headerAndPayload,
                bytes32 r,
                bytes32 s
            ) {
                // Check malleability
                if (uint256(s) > P256_N_DIV_2) {
                    results[i] = false;
                    continue;
                }

                bytes32 messageHash = sha256(headerAndPayload);

                bytes memory input = abi.encodePacked(
                    messageHash,
                    r,
                    s,
                    publicKeysX[i],
                    publicKeysY[i]
                );

                (bool success, bytes memory result) = P256_VERIFIER.staticcall(input);
                results[i] = success && result.length > 0 && uint8(result[0]) == 1;
            } catch {
                // If parsing fails, mark as invalid
                results[i] = false;
            }
        }

        return results;
    }

    /**
     * @notice Get the precompile address being used
     * @return The address of the P-256 precompile
     */
    function getPrecompileAddress() external pure returns (address) {
        return P256_VERIFIER;
    }

    /**
     * @notice Get the secp256r1 curve order
     * @return The curve order n
     */
    function getCurveOrder() external pure returns (uint256) {
        return P256_N;
    }
}
