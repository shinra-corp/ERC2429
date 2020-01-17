pragma solidity >=0.6.0 <0.7.0;

interface IERC2429 {

    event SetupRequested(address indexed who, uint256 activation);
    event Activated(address indexed who);
    event Approved(bytes32 indexed approveHash, address approver, uint256 weight);
    event Execution(address indexed who, bool success);

    /**
     * @notice Cancels a pending setup to change the recovery parameters
     */
    function cancelSetup()
        external;

    /**
     * @notice Configure recovery set parameters of `msg.sender`. `emit Activated(msg.sender)` if there was no previous setup, or `emit SetupRequested(msg.sender, now()+setupDelay)` when reconfiguring.
     * @param _publicHash Hash of `peerHash`.
     * @param _setupDelay Delay for changes being active.
     */
    function setup(
        bytes32 _publicHash,
        uint256 _setupDelay
    )
        external;

    /**
     * @notice Activate a pending setup of recovery parameters
     * @param _who address whih ready setupDelay.
     */
    function activate(address _who)
        external;

    /**
     * @notice Approves a recovery execution. This method is important for when the address is an contract and don't implements EIP1271.
     * @param _approveHash Hash of the recovery call.
     * @param _peerHash seed of `publicHash`
     * @param _weight Amount of weight from the signature
     * @param _ensNode if present, the _proof is checked against _ensNode.
     */
    function approve(
        bytes32 _approveHash,
        bytes32 _peerHash,
        uint256 _weight,
        bytes32 _ensNode
    )
        external;

    /**
     * @notice Approve a recovery execution using an ethereum signed message..
     * @param _approveHash Hash of the recovery call.
     * @param _peerHash seed of `publicHash`.
     * @param _weights Amount of weight from the signature for each signer.
     * @param _ensNodes if present, the _proof is checked against _ensName for the specified signer.
     * @param _signers address of _signature processor. if _signer is a contract, must be ERC1271
     * @param _signatures appended ERC191 signatures.
     */
    function approvePreSigned(
        bytes32 _approveHash,
        bytes32 _peerHash,
        uint256[] calldata _weights,
        bytes32[] calldata _ensNodes,
        address[] calldata _signers,
        bytes calldata _signatures
    )
        external;

    /**
     * @notice executes an approved transaction revaling publicHash hash, friends addresses and set new recovery parameters.
     * @param _executeHash Seed of `peerHash`.
     * @param _merkleRoot Revealed merkle root.
     * @param _weightMultipler How much approval weights are multiplied for.
     * @param _calldest Address will be called.
     * @param _calldata Data to be sent.
     * @param _leafHashes Pre approved leafhashes and it's siblings ordered by descending weight.
     * @param _proofs parents proofs.
     * @param _indexes indexes that select the hashing pairs from calldata `_leafHashes` and `_proofs` and from memory `hashes`.
     */
    function execute(
        bytes32 _executeHash,
        bytes32 _merkleRoot,
        uint256 _weightMultipler,
        address _calldest,
        bytes calldata _calldata,
        bytes32[] calldata _leafHashes,
        bytes32[] calldata _proofs,
        uint256[] calldata _indexes
    )
        external;
}
