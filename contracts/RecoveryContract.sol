pragma solidity >=0.6.0 <0.7.0;

/*
    Implementation of Secret Multisig Recovery - ERC 2429.
    See: https://github.com/ethereum/EIPs/pull/2429
    Discussion: https://ethereum-magicians.org/t/social-recovery-using-address-book-merkle-proofs/3790/18
    Based: https://github.com/status-im/account-contracts/blob/develop/contracts/account/MultisigRecovery.sol
    Autor: 3esmit (status-im)
    Implementor: Axe (Shinra-corp)
*/

import "./IMultiRecovery.sol";
import "./Controller.sol";
import "./ECDSA.sol";
import "./MerkleProof.sol";

contract AccountContract is IMultiRecovery, Controlled {

    bytes32 public publicHash; //Secret that user MUST know to recovery process.
    uint256 public setupDelay; //A reconfiguration SHOULD be possible after a delay period.
    bytes32 public secretThresholdHash; //How many peers is needed for a recovery, MUST keccak256(hash_to_execute, threshold).
    bytes32 public addressListMerkleRoot; //Standard merkle tree, each leaf MUST keccak256(hash_to_peer, ethereum_address).

    uint256 public override nonce;

    Setup private _pendingSetup;

    struct Setup {
        bytes32 public_hash;
        uint256 delay_hours;
        bytes32 threshold_hash;
        bytes32 merkle_root_addresses;
        uint256 setup_timestamp;
    }

    // Save approvals from peers as publicHash => Peer Address => Operation Signed
    mapping(bytes32 => mapping(address => bytes32)) public executionBuffer;

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
    external
    override
    onlyController
    {
        //If is a fresh setup, don´t delay configuration
        if(publicHash == bytes32(0)) {
            publicHash = _publicHash;
            setupDelay = _setupDelay;
            secretThresholdHash = _secretThresholdHash;
            addressListMerkleRoot = _addressListMerkleRoot;
        } else {
            _pendingSetup = Setup(_publicHash, _setupDelay, _secretThresholdHash, addressListMerkleRoot, now);
            emit SetupRequested(now + _setupDelay);
        }
    }


    /**
     * @notice Cancels a pending setup to change the recovery parameters
     */

    function cancelSetup()
        external
        override
        onlyController
    {
        delete _pendingSetup;
        emit SetupRequested(0);
    }

    /**
     * @notice Activate a pending setup of recovery parameters
     */
    function activate()
    external
    override
    {
        require(_pendingSetup.setup_timestamp > 0, "No pending setup");
        require(_pendingSetup.setup_timestamp + setupDelay <= now, "Waiting delay");

        secretThresholdHash = _pendingSetup.threshold_hash;
        setupDelay = _pendingSetup.delay_hours;
        publicHash = _pendingSetup.public_hash;
        addressListMerkleRoot = _pendingSetup.merkle_root_addresses;

        delete _pendingSetup;
        emit Activated();
    }

    /**
     * @notice Approves a recovery.
     * This method is important for when the address is an contract (such as Identity).
     * @param _proofPubHash seed of `publicHash`
     * @param _secretCall Hash of the recovery call
     * @param _proof Merkle proof of friendsMerkleRoot with msg.sender
     * @param _ensName if present, the _proof is checked against _ensName.
     */
    function approve(bytes32 _proofPubHash, bytes32 _secretCall, bytes32[] calldata _proof, bytes calldata _ensName)
    external
    override
    {
        require(MerkleProof.verify(
            _proof,
            addressListMerkleRoot,
            keccak256(abi.encodePacked(_proofPubHash, msg.sender))
        ), "Invalid proof");

        //INCOMPLETE IMPLEMENTATION - ENS RESOLVER and REMOTE CALL

        executionBuffer[publicHash][msg.sender] = _secretCall;
    }


    /**
     * @notice Approve a recovery using an ethereum signed message
     * @param _signer address of _signature processor. if _signer is a contract, must be ERC1271.
     * @param _proofPubHash seed of `publicHash`
     * @param _secretCall Hash of the recovery call
     * @param _proof Merkle proof of friendsMerkleRoot with msg.sender
     * @param _signature ERC191 signature
     * @param _ensName if present, the _proof is checked against _ensName.
     */
    function approvePreSigned(
        address _signer,
        bytes32 _proofPubHash,
        bytes32 _secretCall,
        bytes32[] calldata _proof,
        bytes calldata _signature,
        bytes calldata _ensName
    )
    external
    override
    {
        bytes32 signatureHash = ECDSA.toERC191SignedMessage(
            msg.sender,
            abi.encodePacked(
                controller,
                publicHash,
                _secretCall
            )
        );
        address signer = ECDSA.recover(signatureHash, _signature);
        require(MerkleProof.verify(
            _proof,
            addressListMerkleRoot,
            keccak256(abi.encodePacked(_proofPubHash, msg.sender))
        ), "Invalid proof");
        require(signer != address(0), "Invalid signature");

        //INCOMPLETE IMPLEMENTATION - ENS RESOLVER and REMOTE CALL

        executionBuffer[publicHash][msg.sender] = _secretCall;

        emit Approved(_secretCall, signer);
    }

    /**
     * @notice executes an approved transaction revaling userDataHash hash and friends addresses
     * @param _hashExecute Single hash of User Secret
     * @param _dest Address will be called
     * @param _data Data to be sent
     * @param _friendList friends addresses that approved. Length of this array must be the threshold.
     */
    function execute(
        bytes32 _hashExecute,
        address _dest,
        bytes calldata _data,
        address[] calldata _friendList
    )
    external
    override
    {
        require(publicHash != bytes32(0), "Recovery not set");
        uint256 _threshold = _friendList.length;

        bytes32 _hashPeer = keccak256(abi.encodePacked(_hashExecute));
        require(publicHash == keccak256(abi.encodePacked(_hashPeer)), "Invalid secret");
        require(secretThresholdHash == keccak256(abi.encodePacked(_hashPeer, _threshold)), "Invalid threshold");

        bytes32 callHash = keccak256(
            abi.encodePacked(
                controller,
                _hashPeer,
                _dest,
                _data
            )
        );

        for (uint256 i = 0; i < _threshold; i++) {
            address peer = _friendList[i];
            require(peer != address(0) && executionBuffer[publicHash][peer] == callHash, "Invalid signer");
            delete executionBuffer[publicHash][peer];
        }

        //Here we are already invalidating the current setup
        nonce++;
        //clean up
        //delete executionBuffer[publicHash];
        delete publicHash;
        delete secretThresholdHash;
        delete addressListMerkleRoot;
        delete _pendingSetup;

        bool success;
        (success, ) = _dest.call(_data);
        emit Execution(success);

    }
}
