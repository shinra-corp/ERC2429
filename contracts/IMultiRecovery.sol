pragma solidity >=0.5.0 <0.6.0;

interface IMultiRecovery {

    event SetupRequested(uint256 activation);
    event Activated();
    event Approved(bytes32 indexed secretHash, address approver);
    event Execution(bool success);

    /**
     * @notice Configure recovery parameters `emits Activated()` if there was no previous setup, or `emits SetupRequested(now()+setupDelay)` when reconfiguring.
     * @param _publicHash Double hash of seedPubHash
     * @param _setupDelay Delay for changes being active
     * @param _secretThresholdHash Secret Amount of approvals required
     * @param _addressListMerkleRoot Merkle root of secret address list
     */
    function setup(
        bytes32 _publicHash,
        uint256 _setupDelay,
        bytes32 _secretThresholdHash,
        bytes32 _addressListMerkleRoot
    )
       external;

    /**
     * @notice Cancels a pending setup to change the recovery parameters. `emits PendingSetup(0)` when successful.
     */
    function cancelSetup()
        external;

    /**
     * @notice Activate a pending setup of recovery parameters. `emits Activated()` when successful.
     */
    function activate()
        external;

    /**
     * @notice Approves a recovery.
     * This method is important for when the address is an contract (such as Identity).
     * @param _proofPubHash seed of `publicHash`
     * @param _secretCall Hash of the recovery call
     * @param _proof Merkle proof of friendsMerkleRoot with msg.sender
     * @param _ensName if present, the _proof is checked against _ensName.
     */
    function approve(bytes32 _proofPubHash, bytes32 _secretCall, bytes32[] calldata _proof, bytes calldata _ensName)
        external;

    /**
     * @notice Approve a recovery using an ethereum signed message
     * @param _signer address of _signature processor. if _signer is a contract, must be ERC1271.
     * @param _proofPubHash seed of `publicHash`
     * @param _secretCall Hash of the recovery call
     * @param _proof Merkle proof of friendsMerkleRoot with msg.sender
     * @param _signature ERC191 signature
     * @param _ensName if present, the _proof is checked against _ensName.
     */
    function approvePreSigned(address _signer, bytes32 _proofPubHash, bytes32 _secretCall, bytes32[] calldata _proof, bytes calldata _signature, bytes calldata _ensName)
        external;

    /**
     * @notice executes an approved transaction revaling userDataHash hash and friends addresses
     * @param _seedPubHash Single hash of User Secret
     * @param _dest Address will be called
     * @param _data Data to be sent
     * @param _friendList friends addresses that approved. Length of this array must be the threshold.
     */
    function execute(
        bytes32 _seedPubHash,
        address _dest,
        bytes calldata _data,
        address[] calldata _friendList
    ) external;

    /**
     * @notice reads how many executions this contract already done
     */
    function nonce() external view returns(uint256);
}
