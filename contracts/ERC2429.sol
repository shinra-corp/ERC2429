pragma solidity >=0.6.0 <0.7.0;

/*
    eip: 2429
    title: Secret Multisig Recovery
    author: Ricardo Guilherme Schmidt (ricardo3@status.im), Miguel Mota (@miguelmota), Vitalik Buterin (@vbuterin), naxe (@ngmachado)
    discussions-to: https://ethereum-magicians.org/t/social-recovery-using-address-book-merkle-proofs/3790/
    status: Draft
    type: Standards Track
    category: ERC
    created: 2019-12-07
    requires: 137, 191, 831, 1271, 1344
*/

import "./IERC2429.sol";
import "./interfaces/IENS.sol";
import "./interfaces/IENSResolver.sol";
import "./interfaces/IERC1271.sol";
import "./ECDSA.sol";
import "./MerkleMultiProof.sol";
//import "./SafeMath.sol";

contract ERC2429 is IERC2429 {

 //   using SafeMath for uint256;


    //Needed for EIP-1271 check - bytes4(keccak256("isValidSignature(bytes,bytes)")
    bytes4 constant internal EIP1271_MAGICVALUE = 0x20c13b0b;
    //Weight should sum above this value
    uint256 public constant THRESHOLD = 100 * 10^18;
    //After a recovery Public Hash is discarded
    mapping(bytes32 => bool) public discardedPubHash;
    //Save nonce for each recovery
    mapping(address => uint256) public nonces;
    //Save configurations
    mapping(address => RecoverySet) public configurations;
    //Save approved data
    mapping(bytes32 => Approval) public approved;

    //ENS endpoint contract
    IENS public ens;

    struct RecoverySet {
        bytes32 publicHash;
        uint256 setupDelay;
    }

    struct Approval {
        bytes32 approveHash;
        uint weight;
    }


    event Activated(address indexed who);
    event Approved(bytes32 indexed approveHash, address approver, uint256 weight);
    event Execution(address indexed who, bool success);

    constructor(address _ens) public {
        ens = IENS(_ens);
    }

    /**
     * @notice Configure recovery parameters of `msg.sender`. `emit Activated(msg.sender)` if there was no previous setup, or `emit SetupRequested(msg.sender, now()+setupDelay)` when reconfiguring.
     * @param _publicHash Double hash of executeHash
     * @param _setupDelay Delay for changes being active
     */
    function setup(
        bytes32 _publicHash,
        uint256 _setupDelay
    )
        external
        override
    {
        //filter
        require(!discardedPubHash[_publicHash], "publicHash already used");
        discardedPubHash[_publicHash] = true;

        RecoverySet memory newSet = RecoverySet(_publicHash, _setupDelay);

        require(configurations[msg.sender].publicHash == bytes32(0) ||
                configurations[msg.sender].setupDelay < block.timestamp, 'delay time not meet'
        );

        configurations[msg.sender] = newSet;
        emit Activated(msg.sender);
    }

    /**
     * @notice Approves a recovery. This method is important for when the address is an contract and dont implements EIP1271.
     * @param _approveHash Hash of the recovery call
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
        external
        override
    {
        approveExecution(msg.sender, _approveHash, _peerHash, _weight, _ensNode);
    }

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
        external
        override
    {
        require(_signers.length == _weights.length, 'signers and weight should match');
        for(uint256 i = 0; i <_signers.length; i++) {
            bytes32 signingHash = ECDSA.toERC191SignedMessage(
                address(this), abi.encodePacked(_getChainID(), _approveHash, _peerHash, _weights[i], _ensNodes[i])
            );
            require(_signers[i] != address(0), "Invalid signer");
            require(
                (
                    isContract(_signers[i]) && IERC1271(_signers[i]).isValidSignature(abi.encodePacked(signingHash), _signatures) == EIP1271_MAGICVALUE
                ) || ECDSA.recover(signingHash, _signatures) == _signers[i],
                "Invalid signature");

            approveExecution(_signers[i],  _approveHash, _peerHash, _weights[i], _ensNodes[i]);

        }
    }


    /**
     * @param _signer address of approval signer
     * @param _approveHash Hash of the recovery call
     * @param _peerHash seed of `publicHash`
     * @param _weight Amount of weight from the signature
     * @param _ensNode if present, the _proof is checked against _ensNode.
     */
    function approveExecution(
        address _signer,
        bytes32 _approveHash,
        bytes32 _peerHash,
        uint256 _weight,
        bytes32 _ensNode
    )
        internal
    {
        bool isENS = _ensNode != bytes32(0);
        require(
            !isENS || (
                _signer == IENSResolver(ens.resolver(_ensNode)).addr(_ensNode)
            ),
            "Invalid ENS entry"
        );
        bytes32 leaf = keccak256(abi.encodePacked(_peerHash, _weight, isENS, isENS ? _ensNode : bytes32(uint256(_signer))));
        approved[leaf] = Approval(_approveHash, _weight);
        emit Approved(_approveHash, _signer, _weight);
    }


     /**
     * @notice executes an approved transaction revaling publicHash hash, friends addresses and set new recovery parameters
     * @param _executeHash Seed of `peerHash`
     * @param _merkleRoot Revealed merkle root
     * @param _weightMultipler How much approval weights are multipled for.
     * @param _calldest Address will be called
     * @param _calldata Data to be sent
     * @param _leafHashes Pre approved leafhashes and it's siblings ordered by descending weight
     * @param _proofs parents proofs
     * @param _indexes indexes that select the hashing pairs from calldata `_leafHashes` and `_proofs` and from memory `hashes`
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
        external
        override
    {
        //bytes32 publicHash = configurations[_calldest].publicHash;
        require(configurations[_calldest].publicHash != bytes32(0), "Recovery not set");
        bytes32 peerHash = keccak256(abi.encodePacked(_executeHash));
        require(
            configurations[_calldest].publicHash == keccak256(
                abi.encodePacked(peerHash, _merkleRoot, _weightMultipler)
            ), "merkleRoot, executeHash or weightMultipler is not valid"
        );
        bytes32 approveHash = keccak256(
            abi.encodePacked(
                peerHash,
                _calldest,
                _calldata
            )
        );
        uint256 weight = 0;
        uint256 i = 0;
        while(weight < THRESHOLD){
            bytes32 tempHash = _leafHashes[i];
            require(approved[tempHash].approveHash == approveHash, "Hash not approved");
            weight += approved[tempHash].weight*_weightMultipler;
            delete approved[tempHash];
            i++;
        }

        require(MerkleMultiProof.verifyMerkleMultiproof(_merkleRoot, _leafHashes, _proofs, _indexes), "Invalid leafHashes");
        nonces[_calldest]++;
        delete configurations[_calldest];
        bool success;
        (success, ) = _calldest.call(_calldata);
        emit Execution(_calldest, success);
    }


     /**
     * @dev Internal function to determine if an address is a contract
     * @param _target The address being queried
     * @return result True if `_addr` is a contract
     */
    function isContract(address _target) internal view returns(bool result) {
        assembly {
            result := gt(extcodesize(_target), 0)
        }
    }

    /**
     * @notice get network identification where this contract is running
     */
    function _getChainID() internal pure returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }
}
