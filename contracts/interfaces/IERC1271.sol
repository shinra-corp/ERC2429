pragma solidity >=0.6.0 < 0.7.0;

interface IERC1271
{
    /// @dev Verifies that a signature is valid.
    /// @param data Arbitrary signed data.
    /// @param signature Proof that data has been signed.
    /// @return magicValue bytes4(0x20c13b0b) if the signature check succeeds.
    function isValidSignature(
        bytes calldata data,
        bytes calldata signature
    )
        external
        view
        returns (bytes4 magicValue);
}
