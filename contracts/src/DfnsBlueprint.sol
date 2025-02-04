// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "tnt-core/src/BlueprintServiceManagerBase.sol";

/**
 * @title DfnsBlueprint
 * @dev This contract provides an interface to the DFNS Blueprint Service.
 * @dev For all supported hooks, check the `BlueprintServiceManagerBase` contract.
 */
contract DfnsBlueprint is BlueprintServiceManagerBase {
    /**
     * @dev Converts a public key to an operator address.
     * @param publicKey The public key to convert.
     * @return operator address The operator address.
     */
    function operatorAddressFromPublicKey(bytes calldata publicKey) internal pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }
}